package ve.psmhackaton.totpsoberano

import android.view.View
import android.widget.TextView
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class MainActivityRobolectricTest {

    @Test
    fun launchesLockedWithSpanishHeaderAndHiddenUnlockedPanel() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup().get()
        val title = activity.findViewById<TextView>(R.id.txtAppTitle)
        val panelLocked = activity.findViewById<View>(R.id.panelLocked)
        val panelUnlocked = activity.findViewById<View>(R.id.panelUnlocked)

        assertTrue(title.text.toString().contains("Autenticador Soberano"))
        assertEquals(View.VISIBLE, panelLocked.visibility)
        assertEquals(View.GONE, panelUnlocked.visibility)
    }
}
