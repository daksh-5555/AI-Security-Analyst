import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Button } from "@/components/ui/button";
import { TargetAuthDialog } from "./TargetAuthDialog";

describe("TargetAuthDialog", () => {
  it("requires an explicit confirmation before submitting", async () => {
    const onConfirm = vi.fn().mockResolvedValue(undefined);
    render(
      <TargetAuthDialog mode="authorize" trigger={<Button>Open</Button>} onConfirm={onConfirm} />,
    );

    await userEvent.click(screen.getByRole("button", { name: /open/i }));
    await userEvent.type(screen.getByLabelText(/authorization statement/i), "engagement #1");
    // Submit without checking the confirm box.
    await userEvent.click(screen.getByRole("button", { name: /^authorize$/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/must confirm/i);
    expect(onConfirm).not.toHaveBeenCalled();
  });

  it("submits once the authorization is confirmed", async () => {
    const onConfirm = vi.fn().mockResolvedValue(undefined);
    render(
      <TargetAuthDialog mode="authorize" trigger={<Button>Open</Button>} onConfirm={onConfirm} />,
    );

    await userEvent.click(screen.getByRole("button", { name: /open/i }));
    await userEvent.type(screen.getByLabelText(/authorization statement/i), "engagement #1");
    await userEvent.click(screen.getByRole("checkbox"));
    await userEvent.click(screen.getByRole("button", { name: /^authorize$/i }));

    expect(onConfirm).toHaveBeenCalledWith({ baseUrl: undefined, statement: "engagement #1" });
  });
});
