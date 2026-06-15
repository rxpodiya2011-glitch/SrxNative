#include <jni.h>
#include <string>
#include <cstring>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <android/log.h>
#include <android/api-level.h>
#include <stdlib.h>

#define LOG_TAG "SRX_SEC"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define XOR_KEY 0x55

// ═══════════════════════════════════════════════════════
// 🔐 ENCRYPTED STRINGS (XOR Encrypted)
// ═══════════════════════════════════════════════════════
static std::string decrypt(const unsigned char* enc, int len) {
    std::string res = "";
    for(int i=0; i<len; i++) res += (char)(enc[i] ^ XOR_KEY);
    return res;
}

// 1. Chat Webhook URL (XOR 0x55)
static const unsigned char ENC_WEBHOOK[] = { 0x3d,0x21,0x21,0x25,0x26,0x77,0x7a,0x7a,0x26,0x1a,0x27,0x11,0x21,0x21,0x7a,0x12,0x16,0x16,0x12,0x10,0x7a,0x1a,0x21,0x26,0x7a,0x1a,0x16,0x18,0x7a,0x18,0x1a,0x18,0x27,0x16,0x26,0x7a,0x26,0x7a,0x78,0x66,0x79,0x1a,0x5a,0x22,0x7b,0x38,0x4a,0x4a,0x50,0x54,0x4d,0x5a,0x4a,0x78,0x67,0x77,0x27,0x69,0x49,0x4e,0x51,0x55,0x79,0x7a,0x77,0x3f,0x4d,0x56,0x52,0x7b,0x16,0x68,0x52,0x53,0x66,0x16,0x68,0x79,0x68,0x6e,0x66,0x6e,0x77,0x76,0x7a,0x6e,0x49,0x56,0x66,0x68,0x7a,0x57,0x51,0x53,0x16,0x68,0x47,0x69,0x66,0x53,0x6d,0x12,0x25,0x7b,0x26,0x25,0x7b,0x77,0x7a,0x1a,0x27,0x16,0x12,0x21,0x26,0x7a,0x64,0x57,0x4a,0x5a,0x5b,0x79,0x1a,0x1a,0x1a,0x7b,0x52,0x69,0x57,0x66,0x6e,0x6e,0x64,0x52,0x7b,0x66,0x68,0x57,0x68,0x7a,0x68,0x52,0x69,0x6e,0x64,0x68,0x66,0x64,0x67,0x77,0x66,0x68,0x6e,0x76,0x7b,0x76,0x64,0x68,0x6e,0x7a,0x68,0x25,0x68,0x16 };
// 2. Chat Secret (XOR 0x55)
static const unsigned char ENC_CHAT_SEC[] = { 0x26,0x27,0x2d,0x18,0x78,0x1b,0x27,0x1b,0x12,0x10,0x27,0x18,0x1a,0x3c,0x18,0x1b,0x12,0x10,0x27,0x21,0x18,0x27,0x22,0x1a,0x24,0x18,0x47,0x45,0x47,0x43 };
// 3. Agent Secret (XOR 0x55)
static const unsigned char ENC_AGENT_SEC[] = { 0x26,0x27,0x2d,0x78,0x18,0x34,0x1b,0x34,0x12,0x10,0x27,0x78,0x34,0x3c,0x78,0x34,0x12,0x10,0x1b,0x21,0x78,0x12,0x27,0x1a,0x24,0x78,0x47,0x45,0x47,0x43 };


// 4. Agent Webhook URL (XOR 0x55)
static const unsigned char ENC_AGENT_URL[] = { 0x3d,0x21,0x21,0x25,0x26,0x77,0x7a,0x7a,0x26,0x1a,0x27,0x11,0x21,0x21,0x7a,0x12,0x16,0x16,0x12,0x10,0x7a,0x1a,0x21,0x26,0x7a,0x1a,0x16,0x18,0x7a,0x18,0x1a,0x18,0x27,0x16,0x26,0x7a,0x26,0x7a,0x78,0x66,0x79,0x1a,0x5a,0x22,0x7b,0x38,0x4a,0x4a,0x50,0x54,0x4d,0x5a,0x4a,0x78,0x67,0x77,0x27,0x69,0x49,0x4e,0x51,0x55,0x79,0x7a,0x77,0x3f,0x4d,0x56,0x52,0x7b,0x16,0x68,0x52,0x53,0x66,0x16,0x68,0x79,0x68,0x6e,0x66,0x6e,0x77,0x76,0x7a,0x6e,0x49,0x56,0x66,0x68,0x7a,0x57,0x51,0x53,0x16,0x68,0x47,0x69,0x66,0x53,0x6d,0x12,0x25,0x7b,0x26,0x25,0x7b,0x77,0x7a,0x1a,0x27,0x16,0x12,0x21,0x26,0x7a,0x64,0x57,0x4a,0x5a,0x5b,0x79,0x1a,0x1a,0x1a,0x7b,0x52,0x69,0x57,0x66,0x6e,0x6e,0x64,0x52,0x7b,0x66,0x68,0x57,0x68,0x7a,0x68,0x52,0x69,0x6e,0x64,0x68,0x66,0x64,0x67,0x77,0x66,0x68,0x6e,0x76,0x7b,0x76,0x64,0x68,0x6e,0x7a,0x68,0x25,0x68,0x16 };

extern "C" JNIEXPORT jstring JNICALL
Java_com_srx_manager_NativeLib_getAgentWebhook(JNIEnv* env, jclass clazz, jobject context) {
    if (!isSecure(env, context)) return env->NewStringUTF("blocked");
    std::string url = decrypt(ENC_AGENT_URL, sizeof(ENC_AGENT_URL));
    return env->NewStringUTF(url.c_str());
}





// ═══════════════════════════════════════════════════════
// 🔏 EXPECTED APP SIGNATURE SHA-256 HASH
// ═══════════════════════════════════════════════════════
static const unsigned char EXPECTED_SIGNATURE_SHA256[] = {
    0xA4, 0x0D, 0xA8, 0x0A, 0x59, 0xD1, 0x70, 0xCA, 0xA9, 0x50, 0xCF, 0x15, 0xC1, 0x8C, 0x45, 0x4D, 
    0x47, 0xA3, 0x9B, 0x26, 0x98, 0x9D, 0x8B, 0x64, 0x0E, 0xCD, 0x74, 0x5B, 0xA7, 0x1B, 0xF5, 0xDC
};

// ═══════════════════════════════════════════════════════
// 🛡️ ANTI-FRIDA & ANTI-DEBUG CHECKS
// ═══════════════════════════════════════════════════════
static bool checkMaps() {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return true;
    char line[512]; bool detected = false;
    const char* badLibs[] = { "frida", "gadget", "linjector", "gum-js-loop", "frida-agent", nullptr };
    while (fgets(line, sizeof(line), fp) && !detected) {
        for (int i = 0; badLibs[i] != nullptr; i++) {
            if (strstr(line, badLibs[i])) { detected = true; break; }
        }
    }
    fclose(fp); return !detected;
}

static bool checkDebugger() {
    int fd = open("/proc/self/status", O_RDONLY);
    if (fd < 0) return true;
    char buf[1024] = {0}; read(fd, buf, sizeof(buf) - 1); close(fd);
    char* tracer = strstr(buf, "TracerPid:");
    if (tracer) { int pid = 0; sscanf(tracer, "TracerPid: %d", &pid); if (pid != 0) return false; }
    return true;
}

// ═══════════════════════════════════════════════════════
// 🔏 NATIVE SIGNATURE VERIFICATION (Supports Android 9+)
// ═══════════════════════════════════════════════════════
static bool verifyNativeSignature(JNIEnv* env, jobject context) {
    if (context == nullptr) return false;
    jclass contextClass = env->GetObjectClass(context);
    jmethodID getPM = env->GetMethodID(contextClass, "getPackageManager", "()Landroid/content/pm/PackageManager;");
    jobject pm = env->CallObjectMethod(context, getPM);
    jmethodID getPN = env->GetMethodID(contextClass, "getPackageName", "()Ljava/lang/String;");
    jstring pkgName = (jstring)env->CallObjectMethod(context, getPN);
    
    jclass pmClass = env->GetObjectClass(pm);
    jmethodID getPI = env->GetMethodID(pmClass, "getPackageInfo", "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    
    int apiLevel = android_get_device_api_level();
    jobjectArray sigs = nullptr;
    
    if (apiLevel >= 28) { // Android 9+
        jobject pkgInfo = env->CallObjectMethod(pm, getPI, pkgName, 134217728); // GET_SIGNING_CERTIFICATES
        if (!pkgInfo) return false;
        jclass piClass = env->GetObjectClass(pkgInfo);
        jfieldID siField = env->GetFieldID(piClass, "signingInfo", "Landroid/content/pm/SigningInfo;");
        jobject signingInfo = env->GetObjectField(pkgInfo, siField);
        if (signingInfo) {
            jclass siClass = env->GetObjectClass(signingInfo);
            jmethodID getSigners = env->GetMethodID(siClass, "getApkContentsSigners", "()[Landroid/content/pm/Signature;");
            sigs = (jobjectArray)env->CallObjectMethod(signingInfo, getSigners);
        }
    } else { // Android 8 and below
        jobject pkgInfo = env->CallObjectMethod(pm, getPI, pkgName, 64); // GET_SIGNATURES
        if (!pkgInfo) return false;
        jclass piClass = env->GetObjectClass(pkgInfo);
        jfieldID sigField = env->GetFieldID(piClass, "signatures", "[Landroid/content/pm/Signature;");
        sigs = (jobjectArray)env->GetObjectField(pkgInfo, sigField);
    }
    
    if (!sigs || env->GetArrayLength(sigs) == 0) return false;
    
    jobject sig = env->GetObjectArrayElement(sigs, 0);
    jclass sigClass = env->GetObjectClass(sig);
    jmethodID toBytes = env->GetMethodID(sigClass, "toByteArray", "()[B");
    jbyteArray certBytes = (jbyteArray)env->CallObjectMethod(sig, toBytes);
    
    jclass digestClass = env->FindClass("java/security/MessageDigest");
    jmethodID getInstanceMethod = env->GetStaticMethodID(digestClass, "getInstance", "(Ljava/lang/String;)Ljava/security/MessageDigest;");
    jobject digestObj = env->CallStaticObjectMethod(digestClass, getInstanceMethod, env->NewStringUTF("SHA-256"));
    jmethodID digestMethod = env->GetMethodID(digestClass, "digest", "([B)[B");
    jbyteArray calculatedHashBytes = (jbyteArray)env->CallObjectMethod(digestObj, digestMethod, certBytes);
    
    jsize hashLen = env->GetArrayLength(calculatedHashBytes);
    if (hashLen != 32) return false;
    
    jbyte* actualHash = env->GetByteArrayElements(calculatedHashBytes, nullptr);
    bool match = true;
    for (int i = 0; i < 32; i++) {
        if ((unsigned char)actualHash[i] != EXPECTED_SIGNATURE_SHA256[i]) { match = false; break; }
    }
    env->ReleaseByteArrayElements(calculatedHashBytes, actualHash, JNI_ABORT);
    return match;
}

// ═══════════════════════════════════════════════════════
// MASTER SECURITY CHECK
// ═══════════════════════════════════════════════════════
static bool isSecure(JNIEnv* env, jobject context) {
    if (!checkMaps() || !checkDebugger()) return false;
    if (!verifyNativeSignature(env, context)) {
        LOGE("MODDED APP DETECTED! CRASHING...");
        exit(0); // Mod කරපු App එකක් නම් කෙලින්ම Force Close වෙනවා
        return false;
    }
    return true;
}

// ═══════════════════════════════════════════════════════
// JNI METHODS
// ═══════════════════════════════════════════════════════
extern "C" JNIEXPORT jstring JNICALL
Java_com_srx_manager_NativeLib_getChatWebhook(JNIEnv* env, jclass clazz, jobject context) {
    if (!isSecure(env, context)) return env->NewStringUTF("blocked");
    std::string url = decrypt(ENC_WEBHOOK, sizeof(ENC_WEBHOOK));
    return env->NewStringUTF(url.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_srx_manager_NativeLib_getChatSecret(JNIEnv* env, jclass clazz, jobject context) {
    if (!isSecure(env, context)) return env->NewStringUTF("blocked");
    std::string sec = decrypt(ENC_CHAT_SEC, sizeof(ENC_CHAT_SEC));
    return env->NewStringUTF(sec.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_srx_manager_NativeLib_getAgentSecret(JNIEnv* env, jclass clazz, jobject context) {
    if (!isSecure(env, context)) return env->NewStringUTF("blocked");
    std::string sec = decrypt(ENC_AGENT_SEC, sizeof(ENC_AGENT_SEC));
    return env->NewStringUTF(sec.c_str());
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_srx_manager_NativeLib_isEnvironmentSafe(JNIEnv* env, jclass clazz, jobject context) {
    return isSecure(env, context) ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_srx_manager_NativeLib_isLibraryLoaded(JNIEnv* env, jclass clazz) {
    return JNI_TRUE;
}