import { SidebarDemo } from "@/components/sidebar/app-sidebar";

export default function AnalysisLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <SidebarDemo>
      <main className="flex-1">{children}</main>
    </SidebarDemo>
  );
}
