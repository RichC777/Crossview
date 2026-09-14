import { createRouter, Link } from "@tanstack/react-router";
import { AppErrorComponent } from "@/lib/error-component";
import { routeTree } from "./routeTree.gen";

function NotFound() {
  return (
    <main className="space-y-3">
      <h1 className="text-xl font-medium">Page not found</h1>
      <p className="text-sm text-muted">That path is not in the lab console.</p>
      <Link to="/" className="text-sm text-accent no-underline hover:underline">
        Back to scanner notes
      </Link>
    </main>
  );
}

export const router = createRouter({
  routeTree,
  defaultErrorComponent: AppErrorComponent,
  defaultNotFoundComponent: NotFound,
});

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
