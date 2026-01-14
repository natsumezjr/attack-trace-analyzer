import { SidebarDemo } from "@/components/sidebar/app-sidebar";

export default function DashboardLayout({
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
