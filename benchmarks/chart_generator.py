"""
Pure Python Vector SVG Chart Generator (Zero External Dependencies).
Generates standalone, high-resolution SVG charts for benchmark reports.
"""

from pathlib import Path
from typing import List, Dict, Tuple, Optional, Any


class SVGChartGenerator:
    """Generates clean, responsive SVG line and bar charts with zero external dependencies."""

    @staticmethod
    def _svg_escape(text: str) -> str:
        return (
            str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;")
        )

    @classmethod
    def generate_line_chart(
        cls,
        title: str,
        x_label: str,
        y_label: str,
        x_values: List[Any],
        series: Dict[str, List[float]],
        output_path: Path,
        width: int = 800,
        height: int = 450,
        y_min: Optional[float] = 0.0,
        colors: Optional[List[str]] = None
    ) -> Path:
        """
        Generates a multi-series line chart with grid lines, data dots, and legend.
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        palette = colors or ["#2563eb", "#dc2626", "#16a34a", "#9333ea", "#ea580c"]
        margin_left = 80
        margin_right = 40
        margin_top = 60
        margin_bottom = 60

        plot_width = width - margin_left - margin_right
        plot_height = height - margin_top - margin_bottom

        # Find min/max values
        all_y = [val for vals in series.values() for val in vals if val is not None]
        if not all_y:
            all_y = [0.0]

        max_y = max(all_y)
        min_y = y_min if y_min is not None else min(all_y)
        if max_y == min_y:
            max_y += 1.0

        # Round max_y up nicely
        y_span = max_y - min_y
        y_ticks = 5
        y_step = y_span / y_ticks

        svg_parts = [
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
            f'width="{width}" height="{height}" style="background-color: #ffffff; font-family: -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Helvetica, Arial, sans-serif;">'
        ]

        # Chart Title
        svg_parts.append(
            f'<text x="{width // 2}" y="{margin_top // 2 + 5}" text-anchor="middle" '
            f'font-size="16" font-weight="600" fill="#1e293b">{cls._svg_escape(title)}</text>'
        )

        # Y Axis Grid & Labels
        for i in range(y_ticks + 1):
            val = min_y + i * y_step
            y_pos = margin_top + plot_height - (i * (plot_height / y_ticks))
            # Grid line
            svg_parts.append(
                f'<line x1="{margin_left}" y1="{y_pos}" x2="{width - margin_right}" y2="{y_pos}" '
                f'stroke="#e2e8f0" stroke-width="1" stroke-dasharray="3,3" />'
            )
            # Label
            val_str = f"{val:.1f}" if y_step < 10 else f"{int(round(val)):,}"
            svg_parts.append(
                f'<text x="{margin_left - 10}" y="{y_pos + 4}" text-anchor="end" '
                f'font-size="11" fill="#64748b">{val_str}</text>'
            )

        # X Axis Labels
        n_x = len(x_values)
        x_coords = []
        for i, x_val in enumerate(x_values):
            x_pos = margin_left + (i * (plot_width / max(1, n_x - 1))) if n_x > 1 else margin_left + plot_width // 2
            x_coords.append(x_pos)
            svg_parts.append(
                f'<text x="{x_pos}" y="{margin_top + plot_height + 20}" text-anchor="middle" '
                f'font-size="12" fill="#475569">{cls._svg_escape(str(x_val))}</text>'
            )

        # Axes
        svg_parts.append(
            f'<line x1="{margin_left}" y1="{margin_top}" x2="{margin_left}" y2="{margin_top + plot_height}" stroke="#94a3b8" stroke-width="1.5" />'
        )
        svg_parts.append(
            f'<line x1="{margin_left}" y1="{margin_top + plot_height}" x2="{width - margin_right}" y2="{margin_top + plot_height}" stroke="#94a3b8" stroke-width="1.5" />'
        )

        # Axis Titles
        svg_parts.append(
            f'<text x="{width // 2}" y="{height - 15}" text-anchor="middle" font-size="12" font-weight="500" fill="#334155">{cls._svg_escape(x_label)}</text>'
        )
        svg_parts.append(
            f'<text x="20" y="{margin_top + plot_height // 2}" text-anchor="middle" font-size="12" font-weight="500" fill="#334155" transform="rotate(-90 20 {margin_top + plot_height // 2})">{cls._svg_escape(y_label)}</text>'
        )

        # Series Lines & Dots
        for s_idx, (series_name, y_pts) in enumerate(series.items()):
            color = palette[s_idx % len(palette)]
            pts = []
            valid_coords = []

            for i, val in enumerate(y_pts):
                if val is not None and i < len(x_coords):
                    x_c = x_coords[i]
                    y_c = margin_top + plot_height - ((val - min_y) / max(y_span, 0.0001)) * plot_height
                    pts.append(f"{x_c:.1f},{y_c:.1f}")
                    valid_coords.append((x_c, y_c, val))

            if len(pts) > 1:
                svg_parts.append(
                    f'<polyline fill="none" stroke="{color}" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" points="{" ".join(pts)}" />'
                )

            for x_c, y_c, val in valid_coords:
                svg_parts.append(
                    f'<circle cx="{x_c:.1f}" cy="{y_c:.1f}" r="4" fill="{color}" stroke="#ffffff" stroke-width="1.5" />'
                )

        # Legend
        legend_x = margin_left + 10
        legend_y = margin_top + 15
        for s_idx, series_name in enumerate(series.keys()):
            color = palette[s_idx % len(palette)]
            item_x = legend_x + s_idx * 160
            svg_parts.append(
                f'<rect x="{item_x}" y="{legend_y - 10}" width="12" height="12" fill="{color}" rx="2" />'
            )
            svg_parts.append(
                f'<text x="{item_x + 18}" y="{legend_y}" font-size="11" font-weight="500" fill="#334155">{cls._svg_escape(series_name)}</text>'
            )

        svg_parts.append("</svg>")
        content = "\n".join(svg_parts)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)

        return output_path

    @classmethod
    def generate_bar_chart(
        cls,
        title: str,
        x_label: str,
        y_label: str,
        categories: List[str],
        series: Dict[str, List[float]],
        output_path: Path,
        width: int = 800,
        height: int = 450,
        colors: Optional[List[str]] = None
    ) -> Path:
        """
        Generates a grouped bar chart with legend, value labels, and grid lines.
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        palette = colors or ["#2563eb", "#10b981", "#f59e0b", "#6366f1", "#ec4899"]
        margin_left = 80
        margin_right = 40
        margin_top = 60
        margin_bottom = 60

        plot_width = width - margin_left - margin_right
        plot_height = height - margin_top - margin_bottom

        all_y = [val for vals in series.values() for val in vals if val is not None]
        max_y = max(all_y) if all_y else 1.0
        if max_y <= 0:
            max_y = 1.0
        max_y *= 1.15  # headroom for labels

        y_ticks = 5
        y_step = max_y / y_ticks

        svg_parts = [
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
            f'width="{width}" height="{height}" style="background-color: #ffffff; font-family: -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Helvetica, Arial, sans-serif;">'
        ]

        # Title
        svg_parts.append(
            f'<text x="{width // 2}" y="{margin_top // 2 + 5}" text-anchor="middle" '
            f'font-size="16" font-weight="600" fill="#1e293b">{cls._svg_escape(title)}</text>'
        )

        # Y Axis Grid & Labels
        for i in range(y_ticks + 1):
            val = i * y_step
            y_pos = margin_top + plot_height - (i * (plot_height / y_ticks))
            svg_parts.append(
                f'<line x1="{margin_left}" y1="{y_pos}" x2="{width - margin_right}" y2="{y_pos}" '
                f'stroke="#e2e8f0" stroke-width="1" stroke-dasharray="3,3" />'
            )
            val_str = f"{val:.1f}" if y_step < 10 else f"{int(round(val)):,}"
            svg_parts.append(
                f'<text x="{margin_left - 10}" y="{y_pos + 4}" text-anchor="end" '
                f'font-size="11" fill="#64748b">{val_str}</text>'
            )

        # Bars
        n_cats = len(categories)
        n_series = len(series)
        cat_width = plot_width / max(1, n_cats)
        bar_width = (cat_width * 0.75) / max(1, n_series)
        series_names = list(series.keys())

        for c_idx, cat in enumerate(categories):
            cat_start = margin_left + c_idx * cat_width + (cat_width * 0.125)
            # Category label
            cat_center = margin_left + (c_idx + 0.5) * cat_width
            svg_parts.append(
                f'<text x="{cat_center}" y="{margin_top + plot_height + 20}" text-anchor="middle" '
                f'font-size="12" fill="#475569">{cls._svg_escape(cat)}</text>'
            )

            for s_idx, s_name in enumerate(series_names):
                val = series[s_name][c_idx] if c_idx < len(series[s_name]) else 0.0
                bar_h = (val / max_y) * plot_height if val is not None else 0.0
                bar_x = cat_start + s_idx * bar_width
                bar_y = margin_top + plot_height - bar_h
                color = palette[s_idx % len(palette)]

                svg_parts.append(
                    f'<rect x="{bar_x:.1f}" y="{bar_y:.1f}" width="{bar_width * 0.9:.1f}" height="{bar_h:.1f}" '
                    f'fill="{color}" rx="3" />'
                )
                if val is not None and val > 0:
                    val_str = f"{val:.1f}" if val < 100 else f"{int(round(val)):,}"
                    svg_parts.append(
                        f'<text x="{bar_x + (bar_width * 0.45):.1f}" y="{bar_y - 5:.1f}" text-anchor="middle" '
                        f'font-size="10" font-weight="500" fill="#334155">{val_str}</text>'
                    )

        # Axes
        svg_parts.append(
            f'<line x1="{margin_left}" y1="{margin_top}" x2="{margin_left}" y2="{margin_top + plot_height}" stroke="#94a3b8" stroke-width="1.5" />'
        )
        svg_parts.append(
            f'<line x1="{margin_left}" y1="{margin_top + plot_height}" x2="{width - margin_right}" y2="{margin_top + plot_height}" stroke="#94a3b8" stroke-width="1.5" />'
        )

        # Axis Titles
        svg_parts.append(
            f'<text x="{width // 2}" y="{height - 15}" text-anchor="middle" font-size="12" font-weight="500" fill="#334155">{cls._svg_escape(x_label)}</text>'
        )
        svg_parts.append(
            f'<text x="20" y="{margin_top + plot_height // 2}" text-anchor="middle" font-size="12" font-weight="500" fill="#334155" transform="rotate(-90 20 {margin_top + plot_height // 2})">{cls._svg_escape(y_label)}</text>'
        )

        # Legend
        legend_x = margin_left + 10
        legend_y = margin_top + 15
        for s_idx, s_name in enumerate(series_names):
            color = palette[s_idx % len(palette)]
            item_x = legend_x + s_idx * 160
            svg_parts.append(
                f'<rect x="{item_x}" y="{legend_y - 10}" width="12" height="12" fill="{color}" rx="2" />'
            )
            svg_parts.append(
                f'<text x="{item_x + 18}" y="{legend_y}" font-size="11" font-weight="500" fill="#334155">{cls._svg_escape(s_name)}</text>'
            )

        svg_parts.append("</svg>")
        content = "\n".join(svg_parts)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)

        return output_path
