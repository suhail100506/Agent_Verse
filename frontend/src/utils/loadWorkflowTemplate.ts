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
