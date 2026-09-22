import type { NextConfig } from "next";

const nextConfig: NextConfig = {
	// The repository already has top-level contributor instructions.
	agentRules: false,
	output: "standalone",
};

export default nextConfig;
