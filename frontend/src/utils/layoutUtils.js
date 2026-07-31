import dagre from 'dagre';
import { Position } from '@xyflow/react';

const dagreGraph = new dagre.graphlib.Graph();
dagreGraph.setDefaultEdgeLabel(() => ({}));

export const getLayoutedElements = (nodes, edges, direction = 'LR') => {
  const isHorizontal = direction === 'LR';
  dagreGraph.setGraph({ rankdir: direction, ranksep: 200, nodesep: 100, align: 'UL' });

  nodes.forEach((node) => {
    // Estimating standard agent node size: width ~ 300, height ~ 180
    dagreGraph.setNode(node.id, { width: 300, height: 180 });
  });

  edges.forEach((edge) => {
    dagreGraph.setEdge(edge.source, edge.target);
  });

  dagre.layout(dagreGraph);

  const layoutedNodes = nodes.map((node) => {
    const nodeWithPosition = dagreGraph.node(node.id);
    
    // We want the node to be slightly staggered or positioned beautifully
    return {
      ...node,
      targetPosition: isHorizontal ? Position.Left : Position.Top,
      sourcePosition: isHorizontal ? Position.Right : Position.Bottom,
      position: {
        x: nodeWithPosition.x - 300 / 2, // Centering adjustments
        y: nodeWithPosition.y - 180 / 2,
      },
    };
  });

  return { nodes: layoutedNodes, edges };
};
