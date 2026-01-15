"use client";
import { Graph } from "@antv/g6";
import { Shield, Target, Network } from "lucide-react";
import { useEffect, useRef } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { Card, CardContent } from "@/components/card/card2";

export default () => {
  const containerRef = useRef<HTMLDivElement>(null);
  const graphRef = useRef<Graph | null>(null);

  useEffect(() => {
    if (!containerRef.current) return;
    let cancelled = false;
    let graph: Graph | null = null;

    const init = () => {
      if (cancelled || !containerRef.current) return;
      const width = containerRef.current.clientWidth || 600;
      const height = containerRef.current.clientHeight || 360;

      const toDataUrl = (svg: string) =>
        `data:image/svg+xml;utf8,${encodeURIComponent(svg)}`;

      const shieldSrc = toDataUrl(renderToStaticMarkup(<Shield size={20} />));
      const targetSrc = toDataUrl(renderToStaticMarkup(<Target size={20} />));
      const networkSrc = toDataUrl(renderToStaticMarkup(<Network size={20} />));

      graph = new Graph({
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
    };

    const rafId = requestAnimationFrame(init);
    return () => {
      cancelled = true;
      cancelAnimationFrame(rafId);
      if (graphRef.current) {
        graphRef.current.destroy();
        graphRef.current = null;
      }
      graph = null;
    };
  }, []);

  return (
    <div className="flex h-[calc(100vh-96px)] flex-col p-6">
      <h1 className="mb-6 text-2xl font-semibold text-foreground">溯源分析</h1>
      <Card className="flex h-full flex-col">
        <CardContent className="flex-1">
          <div ref={containerRef} className="h-full w-full" />
        </CardContent>
      </Card>
    </div>
  );
};
