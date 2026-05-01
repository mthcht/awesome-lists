rule Trojan_Win64_Disco_CM_2147908976_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Disco.CM!MTB"
        threat_id = "2147908976"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Disco"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {30 4c 05 39 48 03 c7 48 83 f8 07 73 05 8a 4d 38 eb}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Disco_SBB_2147931433_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Disco.SBB!MTB"
        threat_id = "2147931433"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Disco"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 44 24 20 02 00 00 00 ff 15 df 1b 02 00 48 8b 3d f0 1c 02 00 49 89 c4 8a 03 48 ff c3 4d 89 e9 41 b8 01 00 00 00 48 c7 44 24 20 00 00 00 00 48 89 ea 4c 89 e1 83 f0 aa 88 44 24 4b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Disco_MX_2147955785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Disco.MX!MTB"
        threat_id = "2147955785"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Disco"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "37"
        strings_accuracy = "High"
    strings:
        $x_30_1 = "C:\\Users\\Jicu\\source\\repos\\externalstealer\\x64\\Release\\externalstealer.pdb" ascii //weight: 30
        $x_1_2 = "discord.com/api/webhooks" ascii //weight: 1
        $x_1_3 = "taskkill /IM" ascii //weight: 1
        $x_5_4 = "YandexBrowser\\User Data\\Default\\Local Storage\\leveldb" ascii //weight: 5
        $x_5_5 = "Brave-Browser\\User Data\\Default\\Local Storage\\leveldb" ascii //weight: 5
        $x_5_6 = "Chrome\\User Data\\Default\\Local Storage\\leveldb" ascii //weight: 5
        $x_5_7 = "Opera" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_30_*) and 1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((1 of ($x_30_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Disco_MX_2147955785_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Disco.MX!MTB"
        threat_id = "2147955785"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Disco"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d0 48 8d 8c 24 a0 02 00 00 e8 ?? ?? ?? ?? 48 8b d8 48 8d 94 24 e0 02 00 00 48 8d 8c 24 c0 02 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = "SELECT guid, value_encrypted FROM local_stored_cvc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Disco_SX_2147965024_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Disco.SX!MTB"
        threat_id = "2147965024"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Disco"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "[+] Webcam streaming started" ascii //weight: 10
        $x_10_2 = "[-] Screen streaming" ascii //weight: 10
        $x_5_3 = "RemoteChatWnd" ascii //weight: 5
        $x_1_4 = "JumpscareCls" ascii //weight: 1
        $x_1_5 = "BlankScreenCls" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Disco_GXH_2147965890_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Disco.GXH!MTB"
        threat_id = "2147965890"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Disco"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Vboxguest.syssandboxvirusmalwareGlobalMemoryStatusExGetSystemInfouser32.dllGetSystemMetricsiphlpapi.dllGetAdaptersInfo" ascii //weight: 1
        $x_1_2 = "robloxsteamdiscordfacebookinstagramtwitterx" ascii //weight: 1
        $x_1_3 = "Scredit_cards.txt" ascii //weight: 1
        $x_1_4 = "rust_stealer.pdb" ascii //weight: 1
        $x_1_5 = "src\\discord.rs" ascii //weight: 1
        $x_1_6 = "application/jsonTelegram" ascii //weight: 1
        $x_1_7 = "\\stealth.rs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Disco_MK_2147966106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Disco.MK!MTB"
        threat_id = "2147966106"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Disco"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_15_1 = "[+] Task started. Elevated payload should run shortly." ascii //weight: 15
        $x_10_2 = "Kuina_Rust_Extractor_Mutex_V2" ascii //weight: 10
        $x_5_3 = "[-] run_uac_bypass: failed to copy" ascii //weight: 5
        $x_3_4 = "Web Datacredit_cards.txtCredit Cards" ascii //weight: 3
        $x_2_5 = "file All_Passwords.txt" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Disco_MKA_2147966359_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Disco.MKA!MTB"
        threat_id = "2147966359"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Disco"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "screen.screenshot_capture" ascii //weight: 10
        $x_5_2 = "Starting keylog monitor" ascii //weight: 5
        $x_3_3 = "request_audio_devices" ascii //weight: 3
        $x_2_4 = "captureLoop: JPEG encoding failed (empty)" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Disco_KK_2147968222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Disco.KK!MTB"
        threat_id = "2147968222"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Disco"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "{\"name\":\"discord tokens\",\"value\":\"" ascii //weight: 5
        $x_4_2 = "{\"embeds\":[{\"title\":\"loader system log\",\"color\":16776960,\"fields\":[" ascii //weight: 4
        $x_3_3 = "RDTSC Check Failed" ascii //weight: 3
        $x_2_4 = "Suspicious DLL Injected" ascii //weight: 2
        $x_1_5 = "Watchdog:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

