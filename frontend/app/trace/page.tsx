"use client";
import { Graph } from "@antv/g6";
import { Shield, Target, Network } from "lucide-react";
import { useEffect, useRef } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/card/card2";

export default () => {
  const containerRef = useRef<HTMLDivElement>(null);
  const graphRef = useRef<Graph | null>(null);

  useEffect(() => {
    if (!containerRef.current || graphRef.current) return;
    const width = containerRef.current.clientWidth || 600;
    const height = containerRef.current.clientHeight || 360;

    const toDataUrl = (svg: string) =>
      `data:image/svg+xml;utf8,${encodeURIComponent(svg)}`;

    const shieldSrc = toDataUrl(renderToStaticMarkup(<Shield size={20} />));
    const targetSrc = toDataUrl(renderToStaticMarkup(<Target size={20} />));
    const networkSrc = toDataUrl(renderToStaticMarkup(<Network size={20} />));

    const graph = new Graph({
      container: containerRef.current,
      width,
      height,
      data: {
        nodes: [
          {
            id: "node-1",
            type: "image",
            style: { x: 80, y: 120, size: 36, src: shieldSrc },
          },
          {
            id: "node-2",
            type: "image",
            style: { x: 240, y: 120, size: 36, src: targetSrc },
          },
          {
            id: "node-3",
            type: "image",
            style: { x: 160, y: 240, size: 36, src: networkSrc },
          },
        ],
        edges: [
          { id: "edge-1", source: "node-1", target: "node-2" },
          { id: "edge-2", source: "node-2", target: "node-3" },
          { id: "edge-3", source: "node-3", target: "node-1" },
        ],
      },
      behaviors: ["drag-canvas", "zoom-canvas", "drag-element"],
    });

    graphRef.current = graph;
    graph.render();
    return () => {
      if (graphRef.current) {
        graphRef.current.destroy();
        graphRef.current = null;
      }
    };
  }, []);

  return (
    <div className="p-6">
      <Card className="h-full">
        <CardHeader>
          <CardTitle>溯源分析</CardTitle>
        </CardHeader>
        <CardContent>
          <div ref={containerRef} className="h-[360px] w-full" />
        </CardContent>
      </Card>
    </div>
  );
};
