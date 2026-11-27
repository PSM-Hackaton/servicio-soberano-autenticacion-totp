# Reglas R8/ProGuard para Autenticador Soberano TOTP
# Conserva contratos públicos del núcleo criptográfico y seguridad.

-keep class ve.psmhackaton.totpsoberano.core.** { *; }
-keep class ve.psmhackaton.totpsoberano.security.** { *; }

# Eliminar llamadas de depuración Log.v / Log.d en Release
-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
}
