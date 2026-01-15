"use client";
import { Graph } from "@antv/g6";
import { useEffect, useRef } from "react";

export default () => {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const graph = new Graph({
      container: containerRef.current!,
      width: 500,
      height: 500,
      data: {
        nodes: [
          {
            id: "node-1",
            style: { x: 50, y: 100 },
          },
          {
            id: "node-2",
            style: { x: 150, y: 100 },
          },
        ],
        edges: [{ id: "edge-1", source: "node-1", target: "node-2" }],
      },
      behaviors: ["drag-canvas", "zoom-canvas", "drag-element"],
    });

    graph.render();
  }, []);

  return (
    <div>
      <div>Use G6 in react</div>
      <div ref={containerRef} />
    </div>
  );
};
