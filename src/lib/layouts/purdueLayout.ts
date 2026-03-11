/**
 * Custom Cytoscape.js layout: 'purdue'
 *
 * Arranges device nodes into 7 horizontal Purdue Model bands (L0–L5 + unknown).
 * Register once with: cytoscape('layout', 'purdue', PurdueLayout)
 * Use with:           cy.layout({ name: 'purdue' }).run()
 *
 * Node data field `purdueLevel` (number | null) determines band placement.
 * Unknown / null nodes are placed in the L5 (top) band.
 */

/** Visual band definitions — top (index 0) to bottom (index 6). */
export const PURDUE_BANDS: { label: string; color: string; levels: Array<number | null> }[] = [
	{
		label: 'L5 — Enterprise IT / Unknown',
		color: 'rgba(15, 23, 42, 0.55)',
		levels: [5, null]
	},
	{
		label: 'L4 — Business Network',
		color: 'rgba(30, 41, 59, 0.50)',
		levels: [4]
	},
	{
		label: 'L3.5 — DMZ',
		color: 'rgba(51, 65, 85, 0.45)',
		levels: [] // placeholder row — 3.5 not representable as u8
	},
	{
		label: 'L3 — Historian / SCADA Server',
		color: 'rgba(49, 46, 129, 0.40)',
		levels: [3]
	},
	{
		label: 'L2 — HMI / Supervisory',
		color: 'rgba(30, 58, 138, 0.40)',
		levels: [2]
	},
	{
		label: 'L1 — Controller (PLC / RTU)',
		color: 'rgba(6, 78, 59, 0.40)',
		levels: [1]
	},
	{
		label: 'L0 — Field Devices / Sensors',
		color: 'rgba(69, 26, 3, 0.40)',
		levels: [0]
	}
];

/**
 * Map a purdue_level value (or null for unknown) to a band row index.
 * Row 0 = top (L5/unknown), row 6 = bottom (L0).
 */
export function levelToRow(level: number | null | undefined): number {
	if (level === null || level === undefined) return 0; // unknown → L5 band
	if (level >= 5) return 0;
	if (level >= 4) return 1;
	// 3.5 (DMZ) is not representable as u8; skip row 2 for integer levels
	if (level >= 3) return 3;
	if (level >= 2) return 4;
	if (level >= 1) return 5;
	return 6; // L0
}

export class PurdueLayout {
	private options: any;
	private cy: any;

	constructor(options: any) {
		this.options = options;
		this.cy = options.cy;
	}

	run(): this {
		const cy = this.cy;
		const container = cy.container() as HTMLElement | null;
		const width = container ? container.clientWidth : 800;
		const height = container ? container.clientHeight : 600;

		const numRows = PURDUE_BANDS.length; // 7
		const paddingX = 56;
		const paddingY = 32;
		const usableWidth = width - paddingX * 2;
		const rowHeight = (height - paddingY * 2) / numRows;

		// Group device nodes by row
		const rows: Map<number, any[]> = new Map();
		for (let i = 0; i < numRows; i++) rows.set(i, []);

		cy.nodes('.device').forEach((node: any) => {
			const level = node.data('purdueLevel');
			const row = Math.min(levelToRow(level), numRows - 1);
			rows.get(row)!.push(node);
		});

		// Position nodes within each row, evenly spaced horizontally
		rows.forEach((nodes, rowIdx) => {
			if (nodes.length === 0) return;
			// Row 0 is top, row 6 is bottom; centre vertically within the band
			const y = paddingY + (rowIdx + 0.5) * rowHeight;
			const spacing = usableWidth / (nodes.length + 1);
			nodes.forEach((node: any, i: number) => {
				node.position({ x: paddingX + spacing * (i + 1), y });
			});
		});

		cy.trigger('layoutstop');
		return this;
	}

	stop(): this {
		return this;
	}
}
