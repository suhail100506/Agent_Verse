export const emailThreatTemplate = {
  nodes: [
    { typeId: 'node-file-upload', labelOverride: 'Email Input', relativePosition: { x: 0, y: 150 } },
    { typeId: 'agent-phishing', relativePosition: { x: 350, y: 150 } },
    { typeId: 'agent-malware', relativePosition: { x: 700, y: 50 } },
    { typeId: 'agent-incident', relativePosition: { x: 700, y: 250 } },
    { typeId: 'node-final-report', labelOverride: 'Investigation Report', relativePosition: { x: 1050, y: 150 } }
  ],
  edges: [
    { sourceIndex: 0, targetIndex: 1 },
    { sourceIndex: 1, targetIndex: 2 },
    { sourceIndex: 1, targetIndex: 3 },
    { sourceIndex: 2, targetIndex: 4 },
    { sourceIndex: 3, targetIndex: 4 }
  ]
};

