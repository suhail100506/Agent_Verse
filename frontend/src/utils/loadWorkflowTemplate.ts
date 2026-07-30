import { NODE_LIBRARY } from '../data/nodeLibrary';
import { workflowRegistry } from '../templates/workflowRegistry';

export function loadWorkflowTemplate(templateName: string, startPosition: {x: number, y: number}, agentPayloadOverride: any) {
  const template = workflowRegistry[templateName];
  if (!template) return null;
  
  const nodes: any[] = [];
  const edges: any[] = [];
  
  const uniquePrefix = `tmpl-${Date.now()}`;
  
  // Create nodes with relative positioning
  template.nodes.forEach((tmplNode: any, index: number) => {
    const libraryEntry = NODE_LIBRARY.find((n: any) => 
        n.id === tmplNode.typeId || 
        (n.defaultData && n.defaultData.id === tmplNode.typeId)
    );
    
    let nodeData = libraryEntry?.defaultData ? { ...libraryEntry.defaultData } : {};
    
    if (tmplNode.typeId === agentPayloadOverride?.id) {
       nodeData = { ...nodeData, ...agentPayloadOverride };
    }
    
    if (tmplNode.labelOverride) {
       nodeData.label = tmplNode.labelOverride;
    }
    
    nodeData.status = 'idle';
    
    const nodeId = `${uniquePrefix}-${index}`;
    
    nodes.push({
      id: nodeId,
      type: 'agentNode',
      position: { 
        x: startPosition.x + (tmplNode.relativePosition?.x || 0), 
        y: startPosition.y + (tmplNode.relativePosition?.y || 0) 
      },
      data: nodeData
    });
  });
  
  // Explicitly map edges if provided, otherwise fallback to sequential
  if (template.edges) {
    template.edges.forEach((edge: any, i: number) => {
      edges.push({
        id: `edge-${uniquePrefix}-${i}`,
        source: `${uniquePrefix}-${edge.sourceIndex}`,
        target: `${uniquePrefix}-${edge.targetIndex}`,
        animated: true,
        style: { stroke: '#71717a', strokeWidth: 1.5 }
      });
    });
  } else {
    for (let i = 1; i < nodes.length; i++) {
      edges.push({
        id: `edge-${uniquePrefix}-${i}`,
        source: nodes[i - 1].id,
        target: nodes[i].id,
        animated: true,
        style: { stroke: '#71717a', strokeWidth: 1.5 }
      });
    }
  }
  
  return { nodes, edges };
}

export function generateSingleAgentWorkflow(agentData: any, startPosition: {x: number, y: number}) {
  const uniquePrefix = `agent-flow-${Date.now()}`;
  
  // Find ingest and report templates to get their default data
  const ingestEntry = NODE_LIBRARY.find((n: any) => n.id === 'node-file-upload');
  const reportEntry = NODE_LIBRARY.find((n: any) => n.defaultData && n.defaultData.id === 'node-final-report');

  const ingestData = ingestEntry?.defaultData ? { ...ingestEntry.defaultData, label: 'Payload Ingest', status: 'idle' } : { label: 'Payload Ingest', status: 'idle' };
  const reportData = reportEntry?.defaultData ? { ...reportEntry.defaultData, status: 'idle' } : { label: 'Final Security Report', status: 'idle' };
  
  const nodes = [
    {
      id: `${uniquePrefix}-0`,
      type: 'agentNode',
      position: { x: startPosition.x, y: startPosition.y },
      data: ingestData
    },
    {
      id: `${uniquePrefix}-1`,
      type: 'agentNode',
      position: { x: startPosition.x + 380, y: startPosition.y },
      data: { ...agentData, status: 'idle' }
    },
    {
      id: `${uniquePrefix}-2`,
      type: 'agentNode',
      position: { x: startPosition.x + 760, y: startPosition.y },
      data: reportData
    }
  ];

  const edges = [
    {
      id: `edge-${uniquePrefix}-0`,
      source: `${uniquePrefix}-0`,
      target: `${uniquePrefix}-1`,
      animated: true,
      style: { stroke: '#71717a', strokeWidth: 1.5 }
    },
    {
      id: `edge-${uniquePrefix}-1`,
      source: `${uniquePrefix}-1`,
      target: `${uniquePrefix}-2`,
      animated: true,
      style: { stroke: '#71717a', strokeWidth: 1.5 }
    }
  ];

  return { nodes, edges };
}
