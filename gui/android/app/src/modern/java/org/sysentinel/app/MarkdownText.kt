// SPDX-License-Identifier: Apache-2.0
package org.sysentinel.app

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.*
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.TextUnit
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

private val CodeBackground = Color(0xFF0D1117)
private val CodeText     = Color(0xFFD0E8FF)
private val InlineCodeBg = Color(0xFF1A2535)

@Composable
fun MarkdownText(
    text: String,
    modifier: Modifier = Modifier,
    color: Color = Color(0xFFC8D6E5),
    fontSize: TextUnit = 14.sp,
) {
    val segments = remember(text) { splitCodeBlocks(text) }
    SelectionContainer {
        Column(modifier) {
            for (seg in segments) {
                if (seg.isCode) {
                    CodeBlock(seg.content)
                } else {
                    InlineMarkdown(seg.content, color, fontSize)
                }
            }
        }
    }
}

// ── Code block ────────────────────────────────────────────────────────────────

@Composable
private fun CodeBlock(code: String) {
    Box(
        Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp)
            .background(CodeBackground, RoundedCornerShape(6.dp))
            .padding(horizontal = 10.dp, vertical = 8.dp),
    ) {
        Text(
            text = code.trimEnd('\n'),
            color = CodeText,
            fontSize = 12.sp,
            fontFamily = FontFamily.Monospace,
            lineHeight = 18.sp,
        )
    }
}

// ── Inline markdown block (headers + styled spans) ────────────────────────────

@Composable
private fun InlineMarkdown(text: String, color: Color, fontSize: TextUnit) {
    if (text.isBlank()) return
    val lines = text.split('\n')
    Column {
        for (line in lines) {
            val (prefix, body, sizeMult) = parseHeader(line)
            if (prefix.isNotEmpty()) {
                // Header — bold + scaled size + top padding
                val headerSize = when (prefix.length) {
                    1 -> (fontSize.value * 1.50f).sp
                    2 -> (fontSize.value * 1.25f).sp
                    else -> (fontSize.value * 1.10f).sp
                }
                if (prefix.length == 1) Spacer(Modifier.height(6.dp))
                Text(
                    text = buildInlineAnnotated(body.trim(), color),
                    color = color,
                    fontSize = headerSize,
                    fontWeight = FontWeight.Bold,
                    lineHeight = (headerSize.value * 1.3f).sp,
                )
                Spacer(Modifier.height(2.dp))
            } else {
                val annotated = buildInlineAnnotated(line, color)
                if (annotated.text.isEmpty()) {
                    Spacer(Modifier.height(4.dp))
                } else {
                    Text(
                        text = annotated,
                        color = color,
                        fontSize = fontSize,
                        lineHeight = (fontSize.value * 1.4f).sp,
                    )
                }
            }
        }
    }
}

// ── Inline span parser (bold, italic, inline-code) ────────────────────────────

private fun buildInlineAnnotated(text: String, color: Color): AnnotatedString {
    return buildAnnotatedString {
        var i = 0
        while (i < text.length) {
            when {
                // Code block fence that leaked in — shouldn't happen but guard anyway
                text.startsWith("```", i) -> {
                    val end = text.indexOf("```", i + 3)
                    if (end != -1) {
                        val code = text.substring(i + 3, end)
                        withStyle(SpanStyle(
                            fontFamily = FontFamily.Monospace,
                            background = InlineCodeBg,
                            color = CodeText,
                            fontSize = 12.sp,
                        )) { append(code) }
                        i = end + 3
                    } else { append(text[i]); i++ }
                }
                // Inline code: `code`
                text[i] == '`' -> {
                    val end = text.indexOf('`', i + 1)
                    if (end != -1) {
                        withStyle(SpanStyle(
                            fontFamily = FontFamily.Monospace,
                            background = InlineCodeBg,
                            color = CodeText,
                            fontSize = 12.sp,
                        )) { append(text.substring(i + 1, end)) }
                        i = end + 1
                    } else { append(text[i]); i++ }
                }
                // Bold **text** or __text__
                (text.startsWith("**", i) || text.startsWith("__", i)) -> {
                    val delim = text.substring(i, i + 2)
                    val end = text.indexOf(delim, i + 2)
                    if (end != -1) {
                        withStyle(SpanStyle(fontWeight = FontWeight.Bold)) {
                            append(buildInlineAnnotated(text.substring(i + 2, end), color))
                        }
                        i = end + 2
                    } else { append(text[i]); i++ }
                }
                // Bold *text* (single asterisk, Telegram style)
                text[i] == '*' && (i == 0 || text[i - 1] != '*') -> {
                    val end = findClosingAsterisk(text, i + 1)
                    if (end != -1) {
                        withStyle(SpanStyle(fontWeight = FontWeight.Bold)) {
                            append(buildInlineAnnotated(text.substring(i + 1, end), color))
                        }
                        i = end + 1
                    } else { append(text[i]); i++ }
                }
                // Italic _text_
                text[i] == '_' && (i == 0 || text[i - 1] != '_') -> {
                    val end = text.indexOf('_', i + 1).takeIf {
                        it != -1 && (it + 1 >= text.length || text[it + 1] != '_')
                    }
                    if (end != null) {
                        withStyle(SpanStyle(fontStyle = FontStyle.Italic)) {
                            append(buildInlineAnnotated(text.substring(i + 1, end), color))
                        }
                        i = end + 1
                    } else { append(text[i]); i++ }
                }
                else -> { append(text[i]); i++ }
            }
        }
    }
}

// Find closing `*` that is not part of `**`
private fun findClosingAsterisk(text: String, from: Int): Int {
    var j = from
    while (j < text.length) {
        if (text[j] == '*') {
            val isDouble = (j + 1 < text.length && text[j + 1] == '*') ||
                           (j > 0 && text[j - 1] == '*')
            if (!isDouble) return j
            j += 2
        } else j++
    }
    return -1
}

// Returns (hashPrefix, bodyWithoutPrefix, unused)
private fun parseHeader(line: String): Triple<String, String, Float> {
    val m = Regex("^(#{1,4})\\s+(.*)$").find(line.trimEnd()) ?: return Triple("", line, 1f)
    return Triple(m.groupValues[1], m.groupValues[2], 1f)
}

// ── Code-block splitter ────────────────────────────────────────────────────────

private data class Segment(val content: String, val isCode: Boolean)

private fun splitCodeBlocks(text: String): List<Segment> {
    val result = mutableListOf<Segment>()
    val fence = "```"
    var i = 0
    while (i < text.length) {
        val start = text.indexOf(fence, i)
        if (start == -1) {
            result += Segment(text.substring(i), isCode = false)
            break
        }
        // Text before the fence
        if (start > i) result += Segment(text.substring(i, start), isCode = false)
        // Skip the opening fence (and optional language tag on the same line)
        val afterFence = text.indexOf('\n', start + fence.length)
            .takeIf { it != -1 }?.plus(1) ?: (start + fence.length)
        val end = text.indexOf(fence, afterFence)
        if (end == -1) {
            // Unclosed fence — treat the rest as code
            result += Segment(text.substring(afterFence), isCode = true)
            break
        }
        result += Segment(text.substring(afterFence, end), isCode = true)
        i = end + fence.length
        // Skip trailing newline after closing fence
        if (i < text.length && text[i] == '\n') i++
    }
    return result.filter { it.content.isNotEmpty() }
}
