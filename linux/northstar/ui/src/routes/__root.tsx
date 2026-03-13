import { createRootRoute, Link, Outlet } from "@tanstack/react-router";
import {
  Server,
  Globe,
  Shield,
  ShieldCheck,
  ClipboardList,
  KeyRound,
  FolderOpen,
} from "lucide-react";
import { Toaster } from "@/components/ui/sonner";
import { InjectNotifications } from "@/components/InjectNotifications";
import { Logo } from "@/components/Logo";
import { useWebSocket } from "../lib/useWebSocket";

function RootComponent() {
  useWebSocket();

  return (
    <div className="min-h-screen text-foreground font-sans selection:bg-primary/30">
      <header className="bg-background/50 backdrop-blur-md border-b border-border sticky top-0 z-10 fiery-header">
        <div className="container mx-auto px-6 h-16 flex items-center justify-between">
          <Link
            to="/"
            className="flex items-center gap-2 hover:opacity-80 transition-opacity"
          >
            <Logo className="w-6 h-6 text-primary fill-primary" />
            <h1 className="text-xl font-bold tracking-tight text-foreground">
              Northstar
            </h1>
          </Link>
          <nav className="flex space-x-1 bg-muted/50 p-1 rounded-lg border border-border/50">
            <Link
              to="/"
              activeProps={{
                className:
                  "bg-primary/10 text-primary shadow-[0_0_10px_rgba(var(--primary),0.1)] ring-1 ring-primary/20",
              }}
              inactiveProps={{
                className:
                  "text-muted-foreground hover:text-foreground hover:bg-muted/50",
              }}
              className="flex items-center gap-2 px-4 py-1.5 rounded-md text-sm font-medium transition-all duration-200"
            >
              <Server className="w-4 h-4" />
              Hosts
            </Link>
            <Link
              to="/services"
              activeProps={{
                className:
                  "bg-primary/10 text-primary shadow-[0_0_10px_rgba(var(--primary),0.1)] ring-1 ring-primary/20",
              }}
              inactiveProps={{
                className:
                  "text-muted-foreground hover:text-foreground hover:bg-muted/50",
              }}
              className="flex items-center gap-2 px-4 py-1.5 rounded-md text-sm font-medium transition-all duration-200"
            >
              <Shield className="w-4 h-4" />
              Services
            </Link>
            <Link
              to="/websites"
              activeProps={{
                className:
                  "bg-primary/10 text-primary shadow-[0_0_10px_rgba(var(--primary),0.1)] ring-1 ring-primary/20",
              }}
              inactiveProps={{
                className:
                  "text-muted-foreground hover:text-foreground hover:bg-muted/50",
              }}
              className="flex items-center gap-2 px-4 py-1.5 rounded-md text-sm font-medium transition-all duration-200"
            >
              <Globe className="w-4 h-4" />
              Websites
            </Link>
            <Link
              to="/passwords"
              activeProps={{
                className:
                  "bg-primary/10 text-primary shadow-[0_0_10px_rgba(var(--primary),0.1)] ring-1 ring-primary/20",
              }}
              inactiveProps={{
                className:
                  "text-muted-foreground hover:text-foreground hover:bg-muted/50",
              }}
              className="flex items-center gap-2 px-4 py-1.5 rounded-md text-sm font-medium transition-all duration-200"
            >
              <KeyRound className="w-4 h-4" />
              Passwords
            </Link>
            <Link
              to="/injects"
              activeProps={{
                className:
                  "bg-primary/10 text-primary shadow-[0_0_10px_rgba(var(--primary),0.1)] ring-1 ring-primary/20",
              }}
              inactiveProps={{
                className:
                  "text-muted-foreground hover:text-foreground hover:bg-muted/50",
              }}
              className="flex items-center gap-2 px-4 py-1.5 rounded-md text-sm font-medium transition-all duration-200"
            >
              <ClipboardList className="w-4 h-4" />
              Injects
            </Link>
            <Link
              to="/files"
              activeProps={{
                className:
                  "bg-primary/10 text-primary shadow-[0_0_10px_rgba(var(--primary),0.1)] ring-1 ring-primary/20",
              }}
              inactiveProps={{
                className:
                  "text-muted-foreground hover:text-foreground hover:bg-muted/50",
              }}
              className="flex items-center gap-2 px-4 py-1.5 rounded-md text-sm font-medium transition-all duration-200"
            >
              <FolderOpen className="w-4 h-4" />
              Files
            </Link>
            <Link
              to="/allowed-ips"
              activeProps={{
                className:
                  "bg-primary/10 text-primary shadow-[0_0_10px_rgba(var(--primary),0.1)] ring-1 ring-primary/20",
              }}
              inactiveProps={{
                className:
                  "text-muted-foreground hover:text-foreground hover:bg-muted/50",
              }}
              className="flex items-center gap-2 px-4 py-1.5 rounded-md text-sm font-medium transition-all duration-200"
            >
              <ShieldCheck className="w-4 h-4" />
              ACL
            </Link>
          </nav>
        </div>
      </header>

      <main className="container mx-auto p-6">
        <Outlet />
      </main>
      <Toaster />
      <InjectNotifications />
    </div>
  );
}

export const Route = createRootRoute({
  component: RootComponent,
});
