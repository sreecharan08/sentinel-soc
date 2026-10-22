package com.sentinel.soc.ui

import android.annotation.SuppressLint
import android.content.Context
import android.graphics.Color
import android.opengl.GLES20
import android.opengl.GLSurfaceView
import android.opengl.Matrix
import android.util.AttributeSet
import android.view.MotionEvent
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.FloatBuffer
import java.nio.ShortBuffer
import javax.microedition.khronos.egl.EGLConfig
import javax.microedition.khronos.opengles.GL10
import kotlin.math.PI
import kotlin.math.acos
import kotlin.math.cos
import kotlin.math.max
import kotlin.math.sin
import kotlin.math.sqrt

/**
 * Real 3D hero: an x-ray fresnel sphere with a wireframe shell and an orbiting particle field (GLES 2.0 port of
 * the Three.js orb in the design reference). Colour and spin speed are the protection state; drag to rotate it;
 * a particle burst fires when a threat appears.
 */
class OrbGLSurfaceView @JvmOverloads constructor(
    context: Context, attrs: AttributeSet? = null
) : GLSurfaceView(context, attrs) {

    private val orb = OrbRenderer()
    private var lastX = 0f
    private var lastY = 0f

    /** True while a finger is rotating the orb; the host disables pull-to-refresh for that time. */
    var onDragging: (Boolean) -> Unit = {}

    init {
        setEGLContextClientVersion(2)
        setRenderer(orb)
        renderMode = RENDERMODE_CONTINUOUSLY
    }

    fun setColor(color: Int) = orb.setColor(color)
    fun setPulsing(active: Boolean) { orb.pulsing = active }
    fun setThreat(active: Boolean) = orb.setThreat(active)

    @SuppressLint("ClickableViewAccessibility")
    override fun onTouchEvent(e: MotionEvent): Boolean {
        when (e.actionMasked) {
            MotionEvent.ACTION_DOWN -> {
                parent?.requestDisallowInterceptTouchEvent(true)
                onDragging(true)
                lastX = e.x; lastY = e.y
            }
            MotionEvent.ACTION_MOVE -> {
                orb.drag((e.x - lastX) * 0.01f, (e.y - lastY) * 0.01f)
                lastX = e.x; lastY = e.y
            }
            MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> {
                parent?.requestDisallowInterceptTouchEvent(false)
                onDragging(false)
            }
        }
        return true
    }
}

private class OrbRenderer : GLSurfaceView.Renderer {
    @Volatile private var rgb = floatArrayOf(0.55f, 0.6f, 0.66f)
    @Volatile var pulsing = false
    @Volatile private var dragX = 0f
    @Volatile private var dragY = 0f
    @Volatile private var burstRequested = false
    private var threat = false

    private var shellProg = 0
    private var pointProg = 0
    private lateinit var sphere: FloatBuffer        // xyz (position == normal on a unit sphere)
    private lateinit var triIdx: ShortBuffer
    private lateinit var lineIdx: ShortBuffer
    private lateinit var cloud: FloatBuffer
    private lateinit var burst: FloatBuffer
    private var triCount = 0
    private var lineCount = 0
    private var cloudCount = 0
    private val burstDirs = FloatArray(BURST_N * 3)
    private val burstPos = FloatArray(BURST_N * 3)
    private var burstT = -1f

    private val proj = FloatArray(16)
    private val view = FloatArray(16)
    private val model = FloatArray(16)
    private val mv = FloatArray(16)
    private val mvp = FloatArray(16)
    private val cloudModel = FloatArray(16)
    private val cloudMvp = FloatArray(16)
    private val tmp = FloatArray(16)

    private var rotY = 0f
    private var rotX = 0f
    private var cloudRot = 0f
    private var last = System.nanoTime()
    private val start = System.nanoTime()

    fun setColor(c: Int) { rgb = floatArrayOf(Color.red(c) / 255f, Color.green(c) / 255f, Color.blue(c) / 255f) }
    fun drag(dx: Float, dy: Float) { dragX += dx; dragY += dy }
    fun setThreat(active: Boolean) {
        if (active && !threat) burstRequested = true
        threat = active
    }

    override fun onSurfaceCreated(gl: GL10?, config: EGLConfig?) {
        GLES20.glClearColor(0x11 / 255f, 0x17 / 255f, 0x1E / 255f, 1f)  // @color/bg_1, the card behind it
        GLES20.glEnable(GLES20.GL_BLEND)
        GLES20.glBlendFunc(GLES20.GL_SRC_ALPHA, GLES20.GL_ONE)            // additive, like the reference
        shellProg = program(SHELL_VS, SHELL_FS)
        pointProg = program(POINT_VS, POINT_FS)
        buildSphere()
        buildCloud()
        for (i in 0 until BURST_N) {
            val th = Math.random() * 2 * PI
            val ph = acos(2 * Math.random() - 1)
            burstDirs[i * 3] = (sin(ph) * cos(th)).toFloat()
            burstDirs[i * 3 + 1] = cos(ph).toFloat()
            burstDirs[i * 3 + 2] = (sin(ph) * sin(th)).toFloat()
        }
        burst = floats(burstPos)
    }

    override fun onSurfaceChanged(gl: GL10?, w: Int, h: Int) {
        GLES20.glViewport(0, 0, w, h)
        Matrix.perspectiveM(proj, 0, 42f, w.toFloat() / max(h, 1), 0.1f, 20f)
        Matrix.setLookAtM(view, 0, 0f, 0f, 3.6f, 0f, 0f, 0f, 0f, 1f, 0f)
    }

    override fun onDrawFrame(gl: GL10?) {
        val now = System.nanoTime()
        val dt = ((now - last) / 1e9f).coerceAtMost(0.05f)
        last = now
        val t = (now - start) / 1e9f
        GLES20.glClear(GLES20.GL_COLOR_BUFFER_BIT)

        val spin = if (pulsing) 1.6f else 0.35f
        rotY += dt * spin + dragX; rotX += dt * spin * 0.4f + dragY
        dragX = 0f; dragY = 0f
        cloudRot -= dt * 0.12f
        val c = rgb

        Matrix.setIdentityM(model, 0)
        Matrix.rotateM(model, 0, deg(rotX), 1f, 0f, 0f)
        Matrix.rotateM(model, 0, deg(rotY), 0f, 1f, 0f)
        Matrix.multiplyMM(mv, 0, view, 0, model, 0)
        Matrix.multiplyMM(mvp, 0, proj, 0, mv, 0)

        val pulse = (if (pulsing) 0.22f else 0.12f) * (0.5f + 0.5f * sin(t * if (pulsing) 7f else 2.2f))

        // Fresnel shell, then its wireframe edges.
        GLES20.glUseProgram(shellProg)
        val aPos = GLES20.glGetAttribLocation(shellProg, "aPos")
        GLES20.glEnableVertexAttribArray(aPos)
        sphere.position(0)
        GLES20.glVertexAttribPointer(aPos, 3, GLES20.GL_FLOAT, false, 0, sphere)
        GLES20.glUniformMatrix4fv(GLES20.glGetUniformLocation(shellProg, "uMvp"), 1, false, mvp, 0)
        GLES20.glUniformMatrix4fv(GLES20.glGetUniformLocation(shellProg, "uMv"), 1, false, mv, 0)
        GLES20.glUniform3f(GLES20.glGetUniformLocation(shellProg, "uColor"), c[0], c[1], c[2])
        val uPulse = GLES20.glGetUniformLocation(shellProg, "uPulse")
        val uFlat = GLES20.glGetUniformLocation(shellProg, "uFlat")
        GLES20.glUniform1f(uPulse, pulse)
        GLES20.glUniform1f(uFlat, 0f)
        triIdx.position(0)
        GLES20.glDrawElements(GLES20.GL_TRIANGLES, triCount, GLES20.GL_UNSIGNED_SHORT, triIdx)
        GLES20.glUniform1f(uFlat, 0.45f)
        lineIdx.position(0)
        GLES20.glDrawElements(GLES20.GL_LINES, lineCount, GLES20.GL_UNSIGNED_SHORT, lineIdx)
        GLES20.glDisableVertexAttribArray(aPos)

        // Ambient motes rotate independently of the shell.
        Matrix.setIdentityM(cloudModel, 0)
        Matrix.rotateM(cloudModel, 0, deg(cloudRot), 0f, 1f, 0f)
        Matrix.multiplyMM(tmp, 0, view, 0, cloudModel, 0)
        Matrix.multiplyMM(cloudMvp, 0, proj, 0, tmp, 0)
        drawPoints(cloud, cloudCount, cloudMvp, c, 0.75f, 7f)

        if (burstRequested) { burstRequested = false; burstT = 0f }
        if (burstT >= 0f) {
            burstT += dt
            val d = burstT * 1.6f
            for (i in burstPos.indices) burstPos[i] = burstDirs[i] * d
            burst.position(0); burst.put(burstPos); burst.position(0)
            drawPoints(burst, BURST_N, mvp, RED, max(0f, 1f - burstT * 0.8f), 9f)
            if (burstT > 1.4f) burstT = -1f
        }
    }

    private fun drawPoints(buf: FloatBuffer, n: Int, m: FloatArray, c: FloatArray, alpha: Float, size: Float) {
        GLES20.glUseProgram(pointProg)
        val aPos = GLES20.glGetAttribLocation(pointProg, "aPos")
        GLES20.glEnableVertexAttribArray(aPos)
        buf.position(0)
        GLES20.glVertexAttribPointer(aPos, 3, GLES20.GL_FLOAT, false, 0, buf)
        GLES20.glUniformMatrix4fv(GLES20.glGetUniformLocation(pointProg, "uMvp"), 1, false, m, 0)
        GLES20.glUniform4f(GLES20.glGetUniformLocation(pointProg, "uColor"), c[0], c[1], c[2], alpha)
        GLES20.glUniform1f(GLES20.glGetUniformLocation(pointProg, "uSize"), size)
        GLES20.glDrawArrays(GLES20.GL_POINTS, 0, n)
        GLES20.glDisableVertexAttribArray(aPos)
    }

    private fun buildSphere() {
        val rings = 14
        val sectors = 18
        val pos = ArrayList<Float>()
        for (r in 0..rings) {
            val phi = PI * r / rings
            for (s in 0..sectors) {
                val th = 2 * PI * s / sectors
                pos += (sin(phi) * cos(th)).toFloat(); pos += cos(phi).toFloat(); pos += (sin(phi) * sin(th)).toFloat()
            }
        }
        val tris = ArrayList<Short>()
        val lines = ArrayList<Short>()
        for (r in 0 until rings) for (s in 0 until sectors) {
            val a = r * (sectors + 1) + s
            val b = a + sectors + 1
            tris += listOf(a, b, a + 1, a + 1, b, b + 1).map { it.toShort() }
            lines += listOf(a, a + 1, a, b).map { it.toShort() }
        }
        sphere = floats(pos.toFloatArray())
        triIdx = shorts(tris.toShortArray()); triCount = tris.size
        lineIdx = shorts(lines.toShortArray()); lineCount = lines.size
    }

    private fun buildCloud() {
        val n = 240
        val pos = FloatArray(n * 3)
        for (i in 0 until n) {
            val y = 1f - (i / (n - 1f)) * 2f
            val rr = sqrt(max(0f, 1f - y * y))
            val th = i * 2.399963f
            val radius = 1.55f + (i % 5) * 0.1f
            pos[i * 3] = cos(th) * rr * radius; pos[i * 3 + 1] = y * radius; pos[i * 3 + 2] = sin(th) * rr * radius
        }
        cloud = floats(pos); cloudCount = n
    }

    private fun deg(rad: Float) = (rad * 180f / PI).toFloat()

    private fun floats(a: FloatArray): FloatBuffer =
        ByteBuffer.allocateDirect(a.size * 4).order(ByteOrder.nativeOrder()).asFloatBuffer().apply { put(a); position(0) }

    private fun shorts(a: ShortArray): ShortBuffer =
        ByteBuffer.allocateDirect(a.size * 2).order(ByteOrder.nativeOrder()).asShortBuffer().apply { put(a); position(0) }

    private fun program(vs: String, fs: String): Int {
        val p = GLES20.glCreateProgram()
        GLES20.glAttachShader(p, shader(GLES20.GL_VERTEX_SHADER, vs))
        GLES20.glAttachShader(p, shader(GLES20.GL_FRAGMENT_SHADER, fs))
        GLES20.glLinkProgram(p)
        val ok = IntArray(1)
        GLES20.glGetProgramiv(p, GLES20.GL_LINK_STATUS, ok, 0)
        check(ok[0] != 0) { "orb shader link failed: " + GLES20.glGetProgramInfoLog(p) }
        return p
    }

    private fun shader(type: Int, src: String): Int {
        val s = GLES20.glCreateShader(type)
        GLES20.glShaderSource(s, src)
        GLES20.glCompileShader(s)
        val ok = IntArray(1)
        GLES20.glGetShaderiv(s, GLES20.GL_COMPILE_STATUS, ok, 0)
        check(ok[0] != 0) { "orb shader compile failed: " + GLES20.glGetShaderInfoLog(s) }
        return s
    }

    companion object {
        private const val BURST_N = 120
        private val RED = floatArrayOf(0xF0 / 255f, 0x52 / 255f, 0x4F / 255f)

        // Unit sphere: the position is also the normal. uFlat > 0 draws the wireframe at a fixed alpha.
        private const val SHELL_VS = """
            attribute vec3 aPos;
            uniform mat4 uMvp;
            uniform mat4 uMv;
            varying vec3 vN;
            varying vec3 vV;
            void main() {
                vec4 p = uMv * vec4(aPos, 1.0);
                vN = normalize((uMv * vec4(aPos, 0.0)).xyz);
                vV = normalize(-p.xyz);
                gl_Position = uMvp * vec4(aPos, 1.0);
            }
        """
        private const val SHELL_FS = """
            precision mediump float;
            uniform vec3 uColor;
            uniform float uPulse;
            uniform float uFlat;
            varying vec3 vN;
            varying vec3 vV;
            void main() {
                if (uFlat > 0.0) { gl_FragColor = vec4(uColor, uFlat); return; }
                float f = pow(1.0 - abs(dot(normalize(vN), normalize(vV))), 2.0);
                float a = clamp(0.1 + f * 0.95 + uPulse, 0.0, 1.0);
                gl_FragColor = vec4(uColor * (0.6 + f), a * 0.55);
            }
        """
        private const val POINT_VS = """
            attribute vec3 aPos;
            uniform mat4 uMvp;
            uniform float uSize;
            void main() {
                gl_Position = uMvp * vec4(aPos, 1.0);
                gl_PointSize = uSize;
            }
        """
        private const val POINT_FS = """
            precision mediump float;
            uniform vec4 uColor;
            void main() {
                float d = length(gl_PointCoord - vec2(0.5));
                if (d > 0.5) discard;
                gl_FragColor = vec4(uColor.rgb, uColor.a * (1.0 - d * 2.0));
            }
        """
    }
}
