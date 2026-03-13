import { useEffect, useRef } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { toast } from "sonner";
import { client } from "../lib/client";

export function InjectNotifications() {
  const navigate = useNavigate();
  // Track which injects we've already alerted about to avoid spam
  const notifiedRef = useRef<Set<number>>(new Set());

  const { data: injects } = useQuery({
    queryKey: ["injects"],
    queryFn: async () => {
      const res = await client.listInjects({});
      return res.injects;
    },
    // Poll every 30 seconds to check for upcoming deadlines
    refetchInterval: 30000,
  });

  useEffect(() => {
    if (!injects) return;

    const now = new Date();
    const fiveMinutesFromNow = new Date(now.getTime() + 5 * 60000);

    injects.forEach((inject) => {
      // Skip if completed or no due date
      if (inject.completed || !inject.due) return;

      const due = inject.due.toDate();

      // Check if due time is in the future but within the next 5 minutes
      if (due > now && due <= fiveMinutesFromNow) {
        // Only notify if we haven't already
        if (!notifiedRef.current.has(inject.id)) {
          toast.warning(`Inject due soon: ${inject.title}`, {
            description: `Due in ${Math.ceil((due.getTime() - now.getTime()) / 60000)} minutes.`,
            duration: 8000, // Keep visible for 8 seconds
            action: {
              label: "View",
              onClick: () => {
                navigate({
                  to: "/injects",
                  search: { injectId: inject.id },
                });
              },
            },
          });

          // Mark as notified
          notifiedRef.current.add(inject.id);
        }
      }
    });
  }, [injects, navigate]);

  return null; // This component is logic-only, renders nothing
}
