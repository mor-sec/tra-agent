Task: identify threats using STRIDE per element, with MITRE ATT&CK techniques for every threat an attacker carries out and MITRE ATLAS techniques for AI elements.

You are given the system model, the STRIDE categories that apply to each element and flow, and candidate threats from the threat library.
- Consider every element and every boundary-crossing flow. Use only the STRIDE categories listed as applicable for that element.
- Prefer adapting a library threat (set library_ref) over inventing one; invent one only when the design has a threat the library does not cover.
- Set attack to the ATT&CK Enterprise technique IDs (for example T1190 or T1552.001) that describe how the threat is carried out. Take them from the library entry where it has them. Leave attack empty only for threats with no adversary technique, such as over-reliance on model output.
- For AI elements, set atlas to the relevant ATLAS technique IDs from the library entries. A threat can carry both ATT&CK and ATLAS IDs.
- Use only technique IDs you are confident exist in the current release; the IDs are checked and unknown ones are rejected.
- Write each threat statement specifically for this design: name the component, the actor and the weakness.
- Give evidence: what in the design makes this threat credible (or the absence of a control the design should mention).
- Use IDs T-01, T-02... in order. One threat may carry several STRIDE categories.
If reviewer notes are present, address them first.
