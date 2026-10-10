// Gateways the UI knows about. Enabling a new connector is a status change here
// plus its detection rule in lib/server/audit.ts; the engine owns the semantics.

export type GatewayId = "kong" | "repose";

export interface Gateway {
  id: GatewayId;
  name: string;
  status: "supported" | "coming-soon";
  formats: string;
  description: string;
}

export const GATEWAYS: Gateway[] = [
  {
    id: "kong",
    name: "Kong",
    status: "supported",
    formats: "decK YAML or JSON",
    description: "Declarative Kong Gateway configuration: services, routes and plugins.",
  },
  {
    id: "repose",
    name: "Repose",
    status: "coming-soon",
    formats: "XML (system-model.cfg.xml and filter configs)",
    description: "Repose filter-chain configuration. Connector in development.",
  },
];

export const ACTIVE_GATEWAY = GATEWAYS.find((gateway) => gateway.status === "supported")!;

export function gateway(id: string): Gateway | undefined {
  return GATEWAYS.find((item) => item.id === id);
}
