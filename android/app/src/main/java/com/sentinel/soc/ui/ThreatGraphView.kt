package com.sentinel.soc.ui

import android.annotation.SuppressLint
import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Typeface
import android.opengl.GLES20
import android.opengl.GLSurfaceView
import android.opengl.Matrix
import android.util.AttributeSet
import android.view.MotionEvent
import android.view.ScaleGestureDetector
import android.view.View
import android.view.ViewConfiguration
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.FloatBuffer
import javax.microedition.khronos.egl.EGLConfig
import javax.microedition.khronos.opengles.GL10
import kotlin.math.abs
import kotlin.math.hypot
import kotlin.math.max

/**
 * GLES 2.0 threat graph: glowing nodes, edges with data pulses running out from the app, drag to rotate,
 * pinch to zoom, tap to select. Projected node positions are handed to [labels] every frame for text.
 */
class ThreatGraphView @JvmOverloads constructor(context: Context, attrs: AttributeSet? = null) :
    GLSurfaceView(context, attrs) {

    var labels: GraphLabelsView? = null
    var onSelect: (Int) -> Unit = {}

    private val r = GraphRenderer()
    private val scaler = ScaleGestureDetector(context, object : ScaleGestureDetector.SimpleOnScaleGestureListener() {
        override fun onScale(d: ScaleGestureDetector): Boolean {
            r.zoom = (r.zoom * d.scaleFactor).coerceIn(0.6f, 2.6f)
            return true
        }
    })
    private val slop = ViewConfiguration.get(context).scaledTouchSlop
    private var downX = 0f
    private var downY = 0f
    private var lastX = 0f
    private var lastY = 0f
    private var moved = false

    init {
        setEGLContextClientVersion(2)
        setRenderer(r)
        renderMode = RENDERMODE_CONTINUOUSLY
    }

    /** [colors] is one ARGB colour per node, in graph order. */
    fun setGraph(graph: ThreatGraph.Graph, colors: IntArray) = queueEvent { r.load(graph, colors) }

    fun select(index: Int) { r.selected = index }

    @SuppressLint("ClickableViewAccessibility")
    override fun onTouchEvent(e: MotionEvent): Boolean {
        scaler.onTouchEvent(e)
        when (e.actionMasked) {
            MotionEvent.ACTION_DOWN -> {
                downX = e.x; downY = e.y; lastX = e.x; lastY = e.y; moved = false
                r.touching = true
            }
            MotionEvent.ACTION_MOVE -> if (!scaler.isInProgress && e.pointerCount == 1) {
                if (hypot(e.x - downX, e.y - downY) > slop) moved = true
                r.drag((e.x - lastX) * 0.008f, (e.y - lastY) * 0.008f)
                lastX = e.x; lastY = e.y
            } else moved = true
            MotionEvent.ACTION_UP -> {
                r.touching = false
                if (!moved) onSelect(labels?.nearest(e.x, e.y) ?: -1)
            }
            MotionEvent.ACTION_CANCEL -> r.touching = false
        }
        return true
    }

    private inner class GraphRenderer : Renderer {
        @Volatile var zoom = 1f
        @Volatile var selected = -1
        @Volatile var touching = false
        @Volatile private var dragX = 0f
        @Volatile private var dragY = 0f

        private var nodeProg = 0
        private var lineProg = 0
        private var nodes: ThreatGraph.Graph? = null
        private var nodeBuf: FloatBuffer? = null      // x y z r g b a size
        private var lineBuf: FloatBuffer? = null      // x y z r g b a
        private var pulseBuf: FloatBuffer? = null
        private var pulseData = FloatArray(0)
        private var lineCount = 0
        private var colors = IntArray(0)

        private val proj = FloatArray(16)
        private val view = FloatArray(16)
        private val model = FloatArray(16)
        private val mvp = FloatArray(16)
        private val tmp = FloatArray(16)
        private val v4 = FloatArray(4)
        private val out = FloatArray(4)
        private var rotX = 0.35f
        private var rotY = 0f
        private var w = 1
        private var h = 1
        private var last = System.nanoTime()
        private val start = System.nanoTime()

        fun drag(dx: Float, dy: Float) { dragX += dx; dragY += dy }

        fun load(g: ThreatGraph.Graph, c: IntArray) {
            nodes = g; colors = c
            val nd = FloatArray(g.nodes.size * 8)
            g.nodes.forEachIndexed { i, n ->
                val col = c[i]
                floatArrayOf(n.x, n.y, n.z, Color.red(col) / 255f, Color.green(col) / 255f, Color.blue(col) / 255f, 1f, n.size)
                    .copyInto(nd, i * 8)
            }
            nodeBuf = floats(nd)
            val ld = FloatArray(g.edges.size * 2 * 7)
            g.edges.forEachIndexed { i, (a, b) ->
                for ((k, idx) in listOf(a, b).withIndex()) {
                    val n = g.nodes[idx]; val col = c[b]
                    floatArrayOf(n.x, n.y, n.z, Color.red(col) / 255f, Color.green(col) / 255f, Color.blue(col) / 255f,
                        if (k == 0) 0.22f else 0.85f).copyInto(ld, (i * 2 + k) * 7)
                }
            }
            lineBuf = floats(ld); lineCount = g.edges.size * 2
            pulseData = FloatArray(g.edges.size * 8)
            pulseBuf = floats(pulseData)
        }

        override fun onSurfaceCreated(gl: GL10?, config: EGLConfig?) {
            GLES20.glClearColor(0x0B / 255f, 0x0F / 255f, 0x14 / 255f, 1f)  // @color/bg_0
            GLES20.glEnable(GLES20.GL_BLEND)
            GLES20.glBlendFunc(GLES20.GL_SRC_ALPHA, GLES20.GL_ONE)
            nodeProg = program(NODE_VS, NODE_FS)
            lineProg = program(LINE_VS, LINE_FS)
        }

        override fun onSurfaceChanged(gl: GL10?, width: Int, height: Int) {
            w = width; h = max(height, 1)
            GLES20.glViewport(0, 0, w, h)
            val aspect = w.toFloat() / h
            Matrix.perspectiveM(proj, 0, 45f, aspect, 0.1f, 40f)
            // Back the camera off until the outer shell (radius ~2.2) fits the narrower screen axis.
            baseDist = max(5f, 1.95f / (0.4142f * minOf(1f, aspect)))
        }

        private var baseDist = 6.2f
        private val ringBuf: FloatBuffer by lazy { floats(FloatArray(8)) }
        private val stars: FloatBuffer by lazy {
            val n = 320
            val d = FloatArray(n * 8)
            for (i in 0 until n) {
                val y = 1f - (i + 0.5f) / n * 2f
                val rr = kotlin.math.sqrt(1f - y * y)
                val th = i * 2.399963f
                val rad = 4.2f + (i % 7) * 0.45f
                floatArrayOf(kotlin.math.cos(th) * rr * rad, y * rad, kotlin.math.sin(th) * rr * rad,
                    0.13f, 0.83f, 0.93f, 0.18f + (i % 3) * 0.08f, 4f).copyInto(d, i * 8)
            }
            floats(d)
        }

        override fun onDrawFrame(gl: GL10?) {
            val now = System.nanoTime()
            val dt = ((now - last) / 1e9f).coerceAtMost(0.05f)
            last = now
            val t = (now - start) / 1e9f
            GLES20.glClear(GLES20.GL_COLOR_BUFFER_BIT)
            val g = nodes ?: return

            if (!touching) rotY += dt * 0.18f
            rotY += dragX; rotX = (rotX + dragY).coerceIn(-1.4f, 1.4f)
            dragX = 0f; dragY = 0f
            val dist = baseDist / zoom
            Matrix.setLookAtM(view, 0, 0f, 0f, dist, 0f, 0f, 0f, 0f, 1f, 0f)
            Matrix.setIdentityM(model, 0)
            Matrix.rotateM(model, 0, Math.toDegrees(rotX.toDouble()).toFloat(), 1f, 0f, 0f)
            Matrix.rotateM(model, 0, Math.toDegrees(rotY.toDouble()).toFloat(), 0f, 1f, 0f)
            Matrix.multiplyMM(tmp, 0, view, 0, model, 0)
            Matrix.multiplyMM(mvp, 0, proj, 0, tmp, 0)

            // Edges (fade from the parent end to the child end).
            GLES20.glUseProgram(lineProg)
            bind(lineProg, "aPos", lineBuf!!, 3, 7, 0)
            bind(lineProg, "aColor", lineBuf!!, 4, 7, 3)
            GLES20.glUniformMatrix4fv(GLES20.glGetUniformLocation(lineProg, "uMvp"), 1, false, mvp, 0)
            GLES20.glLineWidth(2f)
            GLES20.glDrawArrays(GLES20.GL_LINES, 0, lineCount)

            GLES20.glUseProgram(nodeProg)
            GLES20.glUniformMatrix4fv(GLES20.glGetUniformLocation(nodeProg, "uMvp"), 1, false, mvp, 0)
            // Point size is divided by depth in the shader; scale by the camera distance so nodes keep their size.
            GLES20.glUniform1f(GLES20.glGetUniformLocation(nodeProg, "uScale"),
                resources.displayMetrics.density * 1.05f * (dist / 6f))
            drawNodes(stars, 320)

            // Pulses: one packet per edge travelling parent -> child, staggered.
            g.edges.forEachIndexed { i, (a, b) ->
                val f = ((t * 0.45f + i * 0.37f) % 1f)
                val na = g.nodes[a]; val nb = g.nodes[b]; val col = colors[b]
                floatArrayOf(na.x + (nb.x - na.x) * f, na.y + (nb.y - na.y) * f, na.z + (nb.z - na.z) * f,
                    Color.red(col) / 255f, Color.green(col) / 255f, Color.blue(col) / 255f, 1f - f * 0.6f, 9f)
                    .copyInto(pulseData, i * 8)
            }
            pulseBuf!!.position(0); pulseBuf!!.put(pulseData)
            drawNodes(pulseBuf!!, g.edges.size)

            // Nodes; the selected one breathes.
            val sel = selected
            if (sel in g.nodes.indices) {
                val n = g.nodes[sel]; val col = colors[sel]
                ringBuf.position(0)
                ringBuf.put(floatArrayOf(n.x, n.y, n.z, Color.red(col) / 255f, Color.green(col) / 255f,
                    Color.blue(col) / 255f, 0.45f, n.size * (2.2f + 0.4f * kotlin.math.sin(t * 5f))))
                drawNodes(ringBuf, 1)
            }
            drawNodes(nodeBuf!!, g.nodes.size)

            project(g)
        }

        private fun drawNodes(buf: FloatBuffer, n: Int) {
            bind(nodeProg, "aPos", buf, 3, 8, 0)
            bind(nodeProg, "aColor", buf, 4, 8, 3)
            bind(nodeProg, "aSize", buf, 1, 8, 7)
            GLES20.glDrawArrays(GLES20.GL_POINTS, 0, n)
        }

        /** Screen position (px) and a 0..1 nearness for every node, for the label overlay and tap picking. */
        private fun project(g: ThreatGraph.Graph) {
            val l = labels ?: return
            val pts = FloatArray(g.nodes.size * 3)
            val dist = baseDist / zoom
            g.nodes.forEachIndexed { i, n ->
                v4[0] = n.x; v4[1] = n.y; v4[2] = n.z; v4[3] = 1f
                Matrix.multiplyMV(out, 0, mvp, 0, v4, 0)
                val ww = if (abs(out[3]) < 1e-4f) 1e-4f else out[3]
                pts[i * 3] = (out[0] / ww + 1f) / 2f * w
                pts[i * 3 + 1] = (1f - out[1] / ww) / 2f * h
                pts[i * 3 + 2] = ((dist + 2.2f - ww) / 4.4f).coerceIn(0.2f, 1f)
            }
            l.update(pts)
        }

        private fun bind(prog: Int, name: String, buf: FloatBuffer, size: Int, stride: Int, offset: Int) {
            val loc = GLES20.glGetAttribLocation(prog, name)
            buf.position(offset)
            GLES20.glEnableVertexAttribArray(loc)
            GLES20.glVertexAttribPointer(loc, size, GLES20.GL_FLOAT, false, stride * 4, buf)
        }

        private fun floats(a: FloatArray): FloatBuffer =
            ByteBuffer.allocateDirect(a.size * 4).order(ByteOrder.nativeOrder()).asFloatBuffer().apply { put(a); position(0) }

        private fun program(vs: String, fs: String): Int {
            val p = GLES20.glCreateProgram()
            for ((type, src) in listOf(GLES20.GL_VERTEX_SHADER to vs, GLES20.GL_FRAGMENT_SHADER to fs)) {
                val s = GLES20.glCreateShader(type)
                GLES20.glShaderSource(s, src); GLES20.glCompileShader(s)
                val ok = IntArray(1); GLES20.glGetShaderiv(s, GLES20.GL_COMPILE_STATUS, ok, 0)
                check(ok[0] != 0) { "graph shader: " + GLES20.glGetShaderInfoLog(s) }
                GLES20.glAttachShader(p, s)
            }
            GLES20.glLinkProgram(p)
            return p
        }
    }

    private companion object {
        const val NODE_VS = """
            attribute vec3 aPos; attribute vec4 aColor; attribute float aSize;
            uniform mat4 uMvp; uniform float uScale;
            varying vec4 vColor;
            void main() {
                gl_Position = uMvp * vec4(aPos, 1.0);
                gl_PointSize = aSize * uScale * (6.0 / gl_Position.w);
                vColor = aColor;
            }
        """
        const val NODE_FS = """
            precision mediump float;
            varying vec4 vColor;
            void main() {
                float d = length(gl_PointCoord - vec2(0.5)) * 2.0;
                if (d > 1.0) discard;
                float core = 1.0 - smoothstep(0.3, 0.5, d);
                float glow = (1.0 - d) * (1.0 - d);
                gl_FragColor = vec4(vColor.rgb * (0.7 + core * 0.6), vColor.a * (glow * 0.85 + core));
            }
        """
        const val LINE_VS = """
            attribute vec3 aPos; attribute vec4 aColor; uniform mat4 uMvp; varying vec4 vColor;
            void main() { gl_Position = uMvp * vec4(aPos, 1.0); vColor = aColor; }
        """
        const val LINE_FS = """
            precision mediump float; varying vec4 vColor;
            void main() { gl_FragColor = vColor; }
        """
    }
}

/** Text labels drawn over the GL graph at each node's projected position; nearer nodes are brighter. */
class GraphLabelsView @JvmOverloads constructor(context: Context, attrs: AttributeSet? = null) : View(context, attrs) {

    var titles: List<String> = emptyList()
    var colors = IntArray(0)
    /** Which nodes always show a label; the selected node shows one regardless. */
    var alwaysLabelled = BooleanArray(0)
    var selected = -1

    @Volatile private var pts = FloatArray(0)
    private val density = resources.displayMetrics.density
    private val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        typeface = Typeface.MONOSPACE; textSize = 10.5f * density; textAlign = Paint.Align.CENTER
    }
    private val shadow = Paint(paint).apply { color = Color.BLACK; style = Paint.Style.STROKE; strokeWidth = 3f * density }

    fun update(p: FloatArray) {
        pts = p
        postInvalidateOnAnimation()
    }

    /** Index of the node nearest to (x, y) within 40dp, or -1. */
    fun nearest(x: Float, y: Float): Int {
        val p = pts
        var best = -1
        var bestD = 40f * density
        for (i in 0 until p.size / 3) {
            val d = hypot(p[i * 3] - x, p[i * 3 + 1] - y)
            if (d < bestD) { bestD = d; best = i }
        }
        return best
    }

    override fun onDraw(canvas: Canvas) {
        val p = pts
        for (i in 0 until minOf(p.size / 3, titles.size)) {
            if (i != selected && !alwaysLabelled.getOrElse(i) { false }) continue
            val near = p[i * 3 + 2]
            val text = titles[i].let { if (it.length > 22) it.take(21) + "…" else it }
            val y = p[i * 3 + 1] - 14f * density
            paint.color = if (i == selected) Color.WHITE else colors.getOrElse(i) { Color.WHITE }
            paint.alpha = (255 * if (i == selected) 1f else near).toInt()
            shadow.alpha = (paint.alpha * 0.7f).toInt()
            canvas.drawText(text, p[i * 3], y, shadow)
            canvas.drawText(text, p[i * 3], y, paint)
        }
    }
}
