# Authorization Semantics

Use these interpretation rules for the supplied assignment:

- The only authenticated baseline subject is the supplied patient identity (`x-user-id: 301`,
  `x-user-role: patient`).
- The reference-account table provides identifiers and expected roles for testing context. It does
  not provide authenticated sessions, secrets, or credentials for those other accounts.
- Every requested `x-user-role` variation is an attacker-controlled claim sent by the same
  baseline patient. Changing that header does not authenticate the request as a real doctor or
  administrator.
- Test 2 evaluates whether the baseline patient can bypass function-level authorization by claiming
  an elevated role. It does not evaluate whether genuinely authenticated doctors or administrators
  have sensible permissions.
- Therefore, if an endpoint denied to the baseline patient returns protected data or privileged
  functionality solely after an elevated role-header override, that test fails. A denial means the
  tested boundary resisted that attempt.
- Apply the same principal-binding rule to object reads, write requests, and administrator access.
- Base every final result on observed responses. These rules define authorization semantics; they
  do not predetermine whether the target will allow or deny a request.
