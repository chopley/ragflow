import {
  IAgentForm,
  ICategorizeForm,
  ICategorizeItem,
  ICategorizeItemResult,
} from '@/interfaces/database/agent';
import { DSLComponents, RAGFlowNodeType } from '@/interfaces/database/flow';
import { removeUselessFieldsFromValues } from '@/utils/form';
import { Edge, Node, Position, XYPosition } from '@xyflow/react';
import { FormInstance, FormListFieldData } from 'antd';
import { humanId } from 'human-id';
import { curry, get, intersectionWith, isEqual, omit, sample } from 'lodash';
import pipe from 'lodash/fp/pipe';
import isObject from 'lodash/isObject';
import { v4 as uuidv4 } from 'uuid';
import {
  CategorizeAnchorPointPositions,
  NoDebugOperatorsList,
  NodeHandleId,
  NodeMap,
  Operator,
} from './constant';
import { BeginQuery, IPosition } from './interface';

const buildEdges = (
  operatorIds: string[],
  currentId: string,
  allEdges: Edge[],
  isUpstream = false,
  componentName: string,
  nodeParams: Record<string, unknown>,
) => {
  operatorIds.forEach((cur) => {
    const source = isUpstream ? cur : currentId;
    const target = isUpstream ? currentId : cur;
    if (!allEdges.some((e) => e.source === source && e.target === target)) {
      const edge: Edge = {
        id: uuidv4(),
        label: '',
        // type: 'step',
        source: source,
        target: target,
        // markerEnd: {
        //   type: MarkerType.ArrowClosed,
        //   color: 'rgb(157 149 225)',
        //   width: 20,
        //   height: 20,
        // },
      };
      if (componentName === Operator.Categorize && !isUpstream) {
        const categoryDescription =
          nodeParams.category_description as ICategorizeItemResult;

        const name = Object.keys(categoryDescription).find(
          (x) => categoryDescription[x].to === target,
        );

        if (name) {
          edge.sourceHandle = name;
        }
      }
      allEdges.push(edge);
    }
  });
};

export const buildNodesAndEdgesFromDSLComponents = (data: DSLComponents) => {
  const nodes: Node[] = [];
  let edges: Edge[] = [];

  Object.entries(data).forEach(([key, value]) => {
    const downstream = [...value.downstream];
    const upstream = [...value.upstream];
    const { component_name: componentName, params } = value.obj;
    nodes.push({
      id: key,
      type: NodeMap[value.obj.component_name as Operator] || 'ragNode',
      position: { x: 0, y: 0 },
      data: {
        label: componentName,
        name: humanId(),
        form: params,
      },
      sourcePosition: Position.Left,
      targetPosition: Position.Right,
    });

    buildEdges(upstream, key, edges, true, componentName, params);
    buildEdges(downstream, key, edges, false, componentName, params);
  });

  return { nodes, edges };
};

const buildComponentDownstreamOrUpstream = (
  edges: Edge[],
  nodeId: string,
  isBuildDownstream = true,
  nodes: Node[],
) => {
  return edges
    .filter((y) => {
      const node = nodes.find((x) => x.id === nodeId);
      let isNotUpstreamTool = true;
      let isNotUpstreamAgent = true;
      if (isBuildDownstream && node?.data.label === Operator.Agent) {
        // Exclude the tool operator downstream of the agent operator
        isNotUpstreamTool = !y.target.startsWith(Operator.Tool);
        // Exclude the agent operator downstream of the agent operator
        isNotUpstreamAgent = !(
          y.target.startsWith(Operator.Agent) &&
          y.targetHandle === NodeHandleId.AgentTop
        );
      }
      return (
        y[isBuildDownstream ? 'source' : 'target'] === nodeId &&
        isNotUpstreamTool &&
        isNotUpstreamAgent
      );
    })
    .map((y) => y[isBuildDownstream ? 'target' : 'source']);
};

const removeUselessDataInTheOperator = curry(
  (operatorName: string, params: Record<string, unknown>) => {
    if (
      operatorName === Operator.Generate ||
      operatorName === Operator.Categorize
    ) {
      return removeUselessFieldsFromValues(params, '');
    }
    return params;
  },
);
// initialize data for operators without parameters
// const initializeOperatorParams = curry((operatorName: string, values: any) => {
//   if (isEmpty(values)) {
//     return initialFormValuesMap[operatorName as Operator];
//   }
//   return values;
// });

function buildAgentTools(edges: Edge[], nodes: Node[], nodeId: string) {
  const node = nodes.find((x) => x.id === nodeId);
  const params = { ...(node?.data.form ?? {}) };
  if (node && node.data.label === Operator.Agent) {
    const bottomSubAgentEdges = edges.filter(
      (x) => x.source === nodeId && x.sourceHandle === NodeHandleId.AgentBottom,
    );

    (params as IAgentForm).tools = (params as IAgentForm).tools.concat(
      bottomSubAgentEdges.map((x) => {
        const {
          params: formData,
          id,
          name,
        } = buildAgentTools(edges, nodes, x.target);

        return {
          component_name: Operator.Agent,
          id,
          name: name as string, // Cast name to string and provide fallback
          params: { ...formData },
        };
      }),
    );
  }
  return { params, name: node?.data.name, id: node?.id };
}

function filterTargetsBySourceHandleId(edges: Edge[], handleId: string) {
  return edges.filter((x) => x.sourceHandle === handleId).map((x) => x.target);
}

function buildCategorize(edges: Edge[], nodes: Node[], nodeId: string) {
  const node = nodes.find((x) => x.id === nodeId);
  const params = { ...(node?.data.form ?? {}) } as ICategorizeForm;
  if (node && node.data.label === Operator.Categorize) {
    const subEdges = edges.filter((x) => x.source === nodeId);

    const items = params.items || [];

    const nextCategoryDescription = items.reduce<
      ICategorizeForm['category_description']
    >((pre, val) => {
      const key = val.name;
      pre[key] = {
        ...omit(val, 'name', 'uuid'),
        examples: val.examples?.map((x) => x.value) || [],
        to: filterTargetsBySourceHandleId(subEdges, val.uuid),
      };
      return pre;
    }, {});

    params.category_description = nextCategoryDescription;
  }
  return omit(params, 'items');
}

const buildOperatorParams = (operatorName: string) =>
  pipe(
    removeUselessDataInTheOperator(operatorName),
    // initializeOperatorParams(operatorName), // Final processing, for guarantee
  );

const ExcludeOperators = [Operator.Note, Operator.Tool];

export function isBottomSubAgent(edges: Edge[], nodeId?: string) {
  const edge = edges.find(
    (x) => x.target === nodeId && x.targetHandle === NodeHandleId.AgentTop,
  );
  return !!edge;
}

// construct a dsl based on the node information of the graph
export const buildDslComponentsByGraph = (
  nodes: RAGFlowNodeType[],
  edges: Edge[],
  oldDslComponents: DSLComponents,
): DSLComponents => {
  const components: DSLComponents = {};

  nodes
    ?.filter(
      (x) =>
        !ExcludeOperators.some((y) => y === x.data.label) &&
        !isBottomSubAgent(edges, x.id),
    )
    .forEach((x) => {
      const id = x.id;
      const operatorName = x.data.label;
      let params = x?.data.form ?? {};

      switch (operatorName) {
        case Operator.Agent: {
          const { params: formData } = buildAgentTools(edges, nodes, id);
          params = formData;
          break;
        }
        case Operator.Categorize:
          params = buildCategorize(edges, nodes, id);
          break;

        default:
          break;
      }

      components[id] = {
        obj: {
          ...(oldDslComponents[id]?.obj ?? {}),
          component_name: operatorName,
          params: buildOperatorParams(operatorName)(params) ?? {},
        },
        downstream: buildComponentDownstreamOrUpstream(edges, id, true, nodes),
        upstream: buildComponentDownstreamOrUpstream(edges, id, false, nodes),
        parent_id: x?.parentId,
      };
    });

  return components;
};

export const receiveMessageError = (res: any) =>
  res && (res?.response.status !== 200 || res?.data?.code !== 0);

// Replace the id in the object with text
export const replaceIdWithText = (
  obj: Record<string, unknown> | unknown[] | unknown,
  getNameById: (id?: string) => string | undefined,
) => {
  if (isObject(obj)) {
    const ret: Record<string, unknown> | unknown[] = Array.isArray(obj)
      ? []
      : {};
    Object.keys(obj).forEach((key) => {
      const val = (obj as Record<string, unknown>)[key];
      const text = typeof val === 'string' ? getNameById(val) : undefined;
      (ret as Record<string, unknown>)[key] = text
        ? text
        : replaceIdWithText(val, getNameById);
    });

    return ret;
  }

  return obj;
};

export const isEdgeEqual = (previous: Edge, current: Edge) =>
  previous.source === current.source &&
  previous.target === current.target &&
  previous.sourceHandle === current.sourceHandle;

export const buildNewPositionMap = (
  currentKeys: string[],
  previousPositionMap: Record<string, IPosition>,
) => {
  // index in use
  const indexesInUse = Object.values(previousPositionMap).map((x) => x.idx);
  const previousKeys = Object.keys(previousPositionMap);
  const intersectionKeys = intersectionWith(
    previousKeys,
    currentKeys,
    (categoryDataKey: string, positionMapKey: string) =>
      categoryDataKey === positionMapKey,
  );
  // difference set
  const currentDifferenceKeys = currentKeys.filter(
    (x) => !intersectionKeys.some((y: string) => y === x),
  );
  const newPositionMap = currentDifferenceKeys.reduce<
    Record<string, IPosition>
  >((pre, cur) => {
    // take a coordinate
    const effectiveIdxes = CategorizeAnchorPointPositions.map(
      (x, idx) => idx,
    ).filter((x) => !indexesInUse.some((y) => y === x));
    const idx = sample(effectiveIdxes);
    if (idx !== undefined) {
      indexesInUse.push(idx);
      pre[cur] = { ...CategorizeAnchorPointPositions[idx], idx };
    }

    return pre;
  }, {});

  return { intersectionKeys, newPositionMap };
};

export const isKeysEqual = (currentKeys: string[], previousKeys: string[]) => {
  return isEqual(currentKeys.sort(), previousKeys.sort());
};

export const getOperatorIndex = (handleTitle: string) => {
  return handleTitle.split(' ').at(-1);
};

// Get the value of other forms except itself
export const getOtherFieldValues = (
  form: FormInstance,
  formListName: string = 'items',
  field: FormListFieldData,
  latestField: string,
) =>
  (form.getFieldValue([formListName]) ?? [])
    .map((x: any) => {
      return get(x, latestField);
    })
    .filter(
      (x: string) =>
        x !== form.getFieldValue([formListName, field.name, latestField]),
    );

export const generateSwitchHandleText = (idx: number) => {
  return `Case ${idx + 1}`;
};

export const getNodeDragHandle = (nodeType?: string) => {
  return nodeType === Operator.Note ? '.note-drag-handle' : undefined;
};

const splitName = (name: string) => {
  const names = name.split('_');
  const type = names.at(0);
  const index = Number(names.at(-1));

  return { type, index };
};

export const generateNodeNamesWithIncreasingIndex = (
  name: string,
  nodes: RAGFlowNodeType[],
) => {
  const templateNameList = nodes
    .filter((x) => {
      const temporaryName = x.data.name;

      const { type, index } = splitName(temporaryName);

      return (
        temporaryName.match(/_/g)?.length === 1 &&
        type === name &&
        !isNaN(index)
      );
    })
    .map((x) => {
      const temporaryName = x.data.name;
      const { index } = splitName(temporaryName);

      return {
        idx: index,
        name: temporaryName,
      };
    })
    .sort((a, b) => a.idx - b.idx);

  let index: number = 0;
  for (let i = 0; i < templateNameList.length; i++) {
    const idx = templateNameList[i]?.idx;
    const nextIdx = templateNameList[i + 1]?.idx;
    if (idx + 1 !== nextIdx) {
      index = idx + 1;
      break;
    }
  }

  return `${name}_${index}`;
};

export const duplicateNodeForm = (nodeData?: RAGFlowNodeType['data']) => {
  const form: Record<string, any> = { ...(nodeData?.form ?? {}) };

  // Delete the downstream node corresponding to the to field of the Categorize operator
  if (nodeData?.label === Operator.Categorize) {
    form.category_description = Object.keys(form.category_description).reduce<
      Record<string, Record<string, any>>
    >((pre, cur) => {
      pre[cur] = {
        ...form.category_description[cur],
        to: undefined,
      };
      return pre;
    }, {});
  }

  // Delete the downstream nodes corresponding to the yes and no fields of the Relevant operator
  if (nodeData?.label === Operator.Relevant) {
    form.yes = undefined;
    form.no = undefined;
  }

  return {
    ...(nodeData ?? { label: '' }),
    form,
  };
};

export const getDrawerWidth = () => {
  return window.innerWidth > 1278 ? '40%' : 470;
};

export const needsSingleStepDebugging = (label: string) => {
  return !NoDebugOperatorsList.some((x) => (label as Operator) === x);
};

// Get the coordinates of the node relative to the Iteration node
export function getRelativePositionToIterationNode(
  nodes: RAGFlowNodeType[],
  position?: XYPosition, // relative position
) {
  if (!position) {
    return;
  }

  const iterationNodes = nodes.filter(
    (node) => node.data.label === Operator.Iteration,
  );

  for (const iterationNode of iterationNodes) {
    const {
      position: { x, y },
      width,
      height,
    } = iterationNode;
    const halfWidth = (width || 0) / 2;
    if (
      position.x >= x - halfWidth &&
      position.x <= x + halfWidth &&
      position.y >= y &&
      position.y <= y + (height || 0)
    ) {
      return {
        parentId: iterationNode.id,
        position: { x: position.x - x + halfWidth, y: position.y - y },
      };
    }
  }
}

export const generateDuplicateNode = (
  position?: XYPosition,
  label?: string,
) => {
  const nextPosition = {
    x: (position?.x || 0) + 50,
    y: (position?.y || 0) + 50,
  };

  return {
    selected: false,
    dragging: false,
    id: `${label}:${humanId()}`,
    position: nextPosition,
    dragHandle: getNodeDragHandle(label),
  };
};

export function convertToStringArray(
  list?: Array<{ value: string | number | boolean }>,
) {
  if (!Array.isArray(list)) {
    return [];
  }
  return list.map((x) => x.value);
}

export function convertToObjectArray(list: Array<string | number | boolean>) {
  if (!Array.isArray(list)) {
    return [];
  }
  return list.map((x) => ({ value: x }));
}

/**
   * convert the following object into a list
   * 
   * {
      "product_related": {
      "description": "The question is about product usage, appearance and how it works.",
      "examples": "Why it always beaming?\nHow to install it onto the wall?\nIt leaks, what to do?",
      "to": "generate:0"
      }
      }
*/
export const buildCategorizeListFromObject = (
  categorizeItem: ICategorizeItemResult,
) => {
  // Categorize's to field has two data sources, with edges as the data source.
  // Changes in the edge or to field need to be synchronized to the form field.
  return Object.keys(categorizeItem)
    .reduce<Array<ICategorizeItem>>((pre, cur) => {
      // synchronize edge data to the to field

      pre.push({
        name: cur,
        ...categorizeItem[cur],
        examples: convertToObjectArray(categorizeItem[cur].examples),
      });
      return pre;
    }, [])
    .sort((a, b) => a.index - b.index);
};

/**
   * Convert the list in the following form into an object
   * {
    "items": [
      {
        "name": "Categorize 1",
        "description": "111",
        "examples": ["ddd"],
        "to": "Retrieval:LazyEelsStick"
      }
     ]
    }
*/
export const buildCategorizeObjectFromList = (list: Array<ICategorizeItem>) => {
  return list.reduce<ICategorizeItemResult>((pre, cur) => {
    if (cur?.name) {
      pre[cur.name] = {
        ...omit(cur, 'name', 'examples'),
        examples: convertToStringArray(cur.examples),
      };
    }
    return pre;
  }, {});
};

export function getAgentNodeTools(agentNode?: RAGFlowNodeType) {
  const tools: IAgentForm['tools'] = get(agentNode, 'data.form.tools', []);
  return tools;
}

export function getAgentNodeMCP(agentNode?: RAGFlowNodeType) {
  const tools: IAgentForm['mcp'] = get(agentNode, 'data.form.mcp', []);
  return tools;
}

export function mapEdgeMouseEvent(
  edges: Edge[],
  edgeId: string,
  isHovered: boolean,
) {
  const nextEdges = edges.map((element) =>
    element.id === edgeId
      ? {
          ...element,
          data: {
            ...element.data,
            isHovered,
          },
        }
      : element,
  );

  return nextEdges;
}

export function buildBeginQueryWithObject(
  inputs: Record<string, BeginQuery>,
  values: BeginQuery[],
) {
  const nextInputs = Object.keys(inputs).reduce<Record<string, BeginQuery>>(
    (pre, key) => {
      const item = values.find((x) => x.key === key);
      if (item) {
        pre[key] = { ...item };
      }
      return pre;
    },
    {},
  );

  return nextInputs;
}
