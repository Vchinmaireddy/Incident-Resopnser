# How We Built an Incident Response Agent That Remembers Every Postmortem Using Hindsight, tRPC, and Drizzle

At 2 a.m., an analyst opens an alert: 42 failed SSH logins against a production bastion, then one success as `admin`. Someone on this team has handled exactly this before. It was three days ago, it's in a ticket, and the person who fixed it is asleep.

The agent I built exists for that gap. It doesn't try to be clever about security. It tries to remember what your team already learned, and put that next to the new alert before the analyst starts from zero.

## What the system does

The product is a command center for security incidents. An analyst gets an alert, opens the incident, and clicks "Run AI investigation." The agent returns a short brief: the likely pattern, a root-cause hypothesis, the evidence worth checking first, the three most similar past incidents, and what actually fixed them. When the analyst closes the incident, a resolution form captures root cause, investigation steps, final fix, and a lesson. That record becomes memory for the next alert.

The stack is deliberately boring: a React client, a tRPC API on Express, Drizzle over MySQL for the incident store, and [Hindsight](https://github.com/vectorize-io/hindsight) as the memory layer that the agent recalls from and writes back to. The whole product hangs on one loop:

1. **Capture** the signal: title, description, logs, error messages, source IP, target, username, severity.
2. **Recall** resolved incidents that resemble it.
3. **Recommend** evidence checks and actions, anchored to those precedents.
4. **Close the loop** by storing what actually fixed it.

Most of the engineering went into steps 2 and 4, and specifically into deciding what counts as memory.

## The through-line: memory is what happened, not what the agent said

The first version of this idea was a chat window with an LLM and a system prompt full of runbooks. It gave plausible advice and had no idea what our team had done. Every conversation started from nothing, which is exactly the failure I wanted to remove.

The obvious fix is to store the conversations. I decided against that early, and I'd make the same call again. Chat transcripts are full of guesses, dead ends, and suggestions nobody followed. If the agent recalls its own past speculation, it slowly becomes confident about things nobody verified. That is a bad property for a tool people use during a breach.

So the unit of memory is a **resolved incident**, and only a human closing an incident creates one. The schema makes that concrete. An incident carries both the signal fields and the outcome fields, and the outcome fields are null until an analyst fills them in:

```ts
create: publicProcedure.input(z.object({ /* title, description, logs, severity ... */ }))
  .mutation(async ({ input }) => {
    const incidentCode = `INC-${String(Date.now()).slice(-4)}`;
    return createIncident({
      ...input,
      incidentCode,
      status: "new",
      rootCause: null,
      investigation: null,
      recommendedActions: null,
      finalResolution: null,
      lessonsLearned: null,
      isHistorical: 0,
    });
  }),
```

Nothing about a new incident is recallable yet. It becomes memory through exactly one path:

```ts
resolve: publicProcedure.input(z.object({
  incidentId: z.number(),
  rootCause: z.string().min(4),
  investigation: z.string().min(4),
  finalResolution: z.string().min(4),
  lessonsLearned: z.string().min(4),
})).mutation(async ({ input }) => {
  return updateIncident(input.incidentId, {
    rootCause: input.rootCause,
    investigation: input.investigation,
    finalResolution: input.finalResolution,
    lessonsLearned: input.lessonsLearned,
    status: "resolved",
    isHistorical: 1,
  });
}),
```

Four required fields, each a real sentence. The form labels matter more than the validation: it asks for "What actually fixed it," not "What did the agent recommend." The `lessonsLearned` field is prompted with "A future analyst should remember…". That framing produces better memories than a generic notes box, because the analyst is writing to a specific reader.

## Why Hindsight, and what it changed

I wanted the memory layer to be something other than a vector table I had to babysit. [Hindsight](https://hindsight.vectorize.io/) is built around the idea that an agent needs to retain, recall, and reflect on what it has experienced, rather than replay a log of it. That maps well onto incident response, where the raw material is a mess of alerts and log lines, and the durable value is the distilled outcome: pattern, cause, fix, lesson.

Getting the boundaries right took some thought. The [agent memory](https://vectorize.io/what-is-agent-memory) model I settled on has three rules:

- **Retain on resolution, not on alert.** Retention happens inside the `resolve` mutation. That keeps the memory clean and means the write path is a deliberate act with an owner.
- **Recall on the whole signal.** The query is built from title, description, logs, and error messages together, not just the title. Analysts write terrible titles at 2 a.m.
- **Recall returns outcomes, not transcripts.** What comes back is root cause, final resolution, and lesson, because that is what changes an analyst's next ten minutes.

The part I underestimated was how much the quality of recall depends on the quality of the write. Hindsight can only surface what we retained. A one-line resolution like "fixed" is a wasted memory, so the write path is the product surface I sweat over most.

## The recall contract

Before Hindsight sat behind it, recall was a small function that scored token overlap between two incidents. I kept it in the codebase as the reference contract, because its shape is what the rest of the app depends on:

```ts
export function similarityScore(current, candidate) {
  const left = tokens([current.title, current.description, current.logs, current.errorMessages].filter(Boolean).join(" "));
  const right = tokens([candidate.title, candidate.description, candidate.logs, candidate.errorMessages].filter(Boolean).join(" "));
  const shared = Array.from(left).filter(word => right.has(word));
  const phraseBoost = /ssh|login|credential|powershell|phishing|malware|endpoint/i.test(current.title + current.description)
    && /ssh|login|credential|powershell|phishing|malware|endpoint/i.test(candidate.title + candidate.description) ? 0.18 : 0;
  return Math.min(0.98, Math.max(0.2, shared.length / Math.max(6, left.size) + phraseBoost));
}
```

I'm not proud of the `phraseBoost` line. It's a hand-tuned hack that nudges known security vocabulary upward, and it's the kind of thing that works on your five sample incidents and falls over on the fiftieth. It also clamps scores between 0.2 and 0.98, so nothing is ever a perfect match or a total miss. That was a conscious choice: I didn't want the UI ever implying certainty.

Replacing that scorer with recall against Hindsight was the point of the exercise, and the callers didn't change. `similarityScore` is still what the tests pin down: a matching SSH memory must rank above an unrelated PowerShell incident. If a memory backend can't pass that test, it doesn't ship.

## Only resolved incidents can be cited

The single most important line in the analysis path is a filter:

```ts
const historical = allIncidents
  .filter(item => item.id !== incident.id && (item.isHistorical === 1 || item.status === "resolved"))
  .map(item => ({ ...item, matchScore: similarityScore(incident, item) }))
  .sort((a, b) => b.matchScore - a.matchScore)
  .slice(0, 3);

const confidence = historical.length
  ? Math.round(Math.min(94, 62 + historical[0].matchScore * 35))
  : 54;
```

Two decisions are packed in here. First, the agent can never cite an open incident as precedent, including the one it's currently analyzing (`item.id !== incident.id`). Second, confidence is tied to memory. With no relevant history the agent reports 54%, and with a strong match it climbs, but it's capped at 94%. I refuse to show 100% on a hypothesis about an active compromise. An analyst who sees a low number and an empty "similar incidents" panel knows the agent is guessing from general patterns, which is useful information in itself.

The brief itself says so plainly: "Hindsight found 2 relevant memory records to anchor the next investigation steps," or one, or zero. The count is part of the answer.

## What an investigation looks like

Here is the case from the top of this post. The live incident, `INC-0015`:

> 42 failed SSH login attempts from 192.168.1.50 followed by one successful login to the production bastion. `Accepted password for admin`.

The agent classifies the pattern as credential abuse / SSH brute force and pulls the closest resolved incident, `INC-0003`, "SSH brute-force attack." Note that the source IP is different: `185.220.101.14` then, an internal address now. The match comes from behavior, a burst of failures followed by a privileged success, not from an indicator. That's the argument for recalling on the whole signal instead of pattern-matching on IPs.

What the analyst sees:

- **Root cause hypothesis:** compromised or weak privileged credentials.
- **Evidence to check:** SSH auth logs around the first failure, source IP reputation and prior activity, whether the successful session was legitimate, and what commands ran afterward.
- **Previous resolution (INC-0003):** "Account secured and unauthorized access removed," with the lesson "Enable MFA for every privileged account and alert on failure-to-success login bursts."
- **Suggested actions:** disable or step-up authenticate the account, reset credentials and revoke sessions, block the source IP after confirming intent, enable MFA for privileged access.

The second-closest memory, `INC-0007`, is a privileged credential compromise via password reuse. It didn't look like a brute force, but it shares a root-cause family. Surfacing it prompts an analyst to ask whether `admin` reuses a password anywhere, a question the first match alone wouldn't raise.

Every brief ends with two buttons, "Helpful" and "Needs work," which write to a feedback table keyed by incident. I haven't used that signal to change ranking yet, and I'd rather say so than imply a learning loop that isn't there. Right now it tells me which briefs analysts distrust, and that has already been a better bug report than any log.

## Lessons learned

**1. Store outcomes, not conversations.** Memory that includes the agent's own speculation drifts toward confident nonsense. Gate writes behind a human-owned event, and the memory stays trustworthy.

**2. The write path is the product.** Recall quality is capped by what you retained. I spent more time on the resolution form's wording than on any ranking logic, and it paid back more.

**3. Keep the retrieval contract small and testable.** One function, two fixtures, one assertion: SSH beats PowerShell. That test survived swapping the engine underneath, and it's what let me trust the swap.

**4. Make uncertainty visible.** A confidence that drops to 54% when there's no precedent, a hard cap below 100%, and an explicit "N memory records" count all keep the analyst calibrated. If your agent can't say "I have nothing on this," people will stop believing it when it says "I'm sure."

**5. Hand-tuned boosts are debt.** My `phraseBoost` was the fastest way to make five incidents look right and the slowest way to make five hundred behave. If you find yourself adding keyword lists to a ranking function, you want a real memory system instead. That was my reason for reaching for Hindsight, and I'd do it earlier next time.

The idea that guided all of this is that an incident response tool shouldn't be a smarter chat box. It should make the second time you see a problem cheaper than the first. Everything else, the classification, the confidence math, the feedback buttons, is scaffolding around that one property.
