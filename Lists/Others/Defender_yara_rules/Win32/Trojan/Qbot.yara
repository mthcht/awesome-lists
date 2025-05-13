rule Trojan_Win32_Qbot_A_2147735470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.A"
        threat_id = "2147735470"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "265ZXOK5Kc|Z5d_|tKFfOrz7KtueD.pdb" ascii //weight: 1
        $x_1_2 = "previews41georgeKtc" wide //weight: 1
        $x_1_3 = "SincefLbeGoogletheappointment" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_B_2147735570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.B"
        threat_id = "2147735570"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".7R8J7d8npi|Da5u9#mTOwydH4.pdb" ascii //weight: 1
        $x_1_2 = "typedwereJ4jd2aspectsURLs" ascii //weight: 1
        $x_1_3 = "nUsynchronizethetheiradisplayingSeptemberZ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_C_2147735580_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.C"
        threat_id = "2147735580"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "k:\\git\\google\\public\\dns.PDB" ascii //weight: 1
        $x_1_2 = "SlessChromefrom" ascii //weight: 1
        $x_1_3 = "benefitzaO3thesandboxd" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_D_2147735973_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.D"
        threat_id = "2147735973"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "F:\\public\\rel\\gavnosoft.PDB" ascii //weight: 1
        $x_1_2 = "Chromeagainstbyq3jvSH" ascii //weight: 1
        $x_1_3 = "L1zbutter1browsers,Omnibox" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_F_2147739800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.F"
        threat_id = "2147739800"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TaskEsbydFlash" wide //weight: 1
        $x_1_2 = "blacklistsztransferredService.13andmostsystemsbooby-trappedfrom" wide //weight: 1
        $x_1_3 = "barneyjNGE3wasThiscontrolledR" wide //weight: 1
        $x_1_4 = "Sbutfprocess0HAdakotaThereof" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_A_2147740709_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.A!MTB"
        threat_id = "2147740709"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 54 24 10 81 f2 cc 43 32 4f 83 c1 01 89 54 24 24 89 4c 24 1c 8b 54 24 18}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_BA_2147741018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.BA!MTB"
        threat_id = "2147741018"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {3d 65 87 00 00 74 ?? e8 ?? ?? ?? ?? 89 c8 58 8b 3d ?? ?? ?? ?? 40 05 ?? ?? ?? ?? 89 e8 57 83 c0 06 83 e8 01 48 5e 89 47 04 40 05 ?? ?? ?? ?? 58 89 47 0c ba 14 00 00 00 81 2c 32 ?? ?? ?? ?? 8b 14 32 52}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_BA_2147741018_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.BA!MTB"
        threat_id = "2147741018"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 f0 8b 55 08 8b 02 2b c6 8b 4d 08 89 01 5e 8b e5 5d c3}  //weight: 1, accuracy: High
        $x_1_2 = {03 4d fc 8b 15 ?? ?? ?? 00 03 55 fc 8a 02 88 01 8b 4d fc 83 c1 01 89 4d fc eb}  //weight: 1, accuracy: Low
        $x_1_3 = {58 8b e8 8b 15 ?? ?? ?? 00 52 8b 15 ?? ?? ?? 00 52 8b 15 ?? ?? ?? 00 52 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_BM_2147741575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.BM!MTB"
        threat_id = "2147741575"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 1c 3b 89 04 24 8b 44 24 18 0d c6 1c a1 4e 01 f2 88 d7 0f b6 d7 8b 74 24 20 89 74 24 74 89 44 24 70 8a 7c 24 6b 80 c7 a0 8b 44 24 14 8a 04 10 30 d8 88 7c 24 6b 8b 54 24 28 88 04 3a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_SK_2147742120_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.SK!MTB"
        threat_id = "2147742120"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ofCfqremaypowered7" wide //weight: 1
        $x_1_2 = "6cLinuxsjFrenchZ" wide //weight: 1
        $x_1_3 = "jenniferhiddenH" ascii //weight: 1
        $x_1_4 = "y4orhas" wide //weight: 1
        $x_1_5 = "self.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_PA_2147742597_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.PA!MTB"
        threat_id = "2147742597"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 89 e5 57 56 83 e4 ?? 83 ec ?? 8a 45 ?? 8b 4d ?? 8b 55 ?? 8b 75 ?? c6 44 24 ?? ?? 83 fe 00 88 44 24 ?? 89 4c 24 ?? 89 54 24 ?? 89 74 24 ?? 74 ?? 8b 44 24 ?? 05 ?? ?? ?? ?? 8a 4c 24 ?? 89 44 24 ?? 80 c1 ?? 8a 54 24 ?? 28 d1 8b 44 24 ?? 8b 74 24 ?? 8a 2c 30 00 e9 8b 7c 24 ?? 88 0c 37 8a 4c 24 ?? 88 4c 24 ?? 8d 65 ?? 5e 5f 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {0f 31 89 d6 89 c7 0f 31}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_G_2147743619_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.G!MSR"
        threat_id = "2147743619"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\defeat\\rtl49.pdb" ascii //weight: 1
        $x_1_2 = "dsfuckyou10O" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RB_2147743922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RB!MTB"
        threat_id = "2147743922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 d8 8b 1a 03 5d a8 2b d8 4b 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 03 d8 8b 45 d8 89 18 8b 45 c4 03 45 a4 89 45 a0 6a 00 e8 ?? ?? ?? ?? 8b 55 a0 2b d0 4a 8b 45 d8 33 10 89 55 a0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RB_2147743922_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RB!MTB"
        threat_id = "2147743922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 c4 04 8b ?? ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8d 54 01 ?? 2b 55 ?? 03 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 e8 15 a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 4d ?? 03 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 2b 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? b8 01 00 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RB_2147743922_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RB!MTB"
        threat_id = "2147743922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "88"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "comet.yahoo.com;.hiro.tv;safebrowsing.google.com;geo.query.yahoo.com;googleusercontent.co" ascii //weight: 10
        $x_10_2 = ";salesforce.com;officeapps.live.com;storage.live.com;messenger.live.com;.twimg.com;" ascii //weight: 10
        $x_10_3 = "api.skype.com;mail.google.com;.bing.com;playtoga.com" ascii //weight: 10
        $x_10_4 = "siteadvisor.com;avgthreatlabs.com;safeweb.norton.com" ascii //weight: 10
        $x_10_5 = "t=%s time=[%02d:%02d:%02d-%02d/%02d/%d]" ascii //weight: 10
        $x_10_6 = "host=[%s:%u] user=[%s] pass=[%s]" ascii //weight: 10
        $x_10_7 = "url=[%s] user=[%s] pass=[%s]" ascii //weight: 10
        $x_10_8 = "facebook.com/login" ascii //weight: 10
        $x_1_9 = "avcuf32.dll" ascii //weight: 1
        $x_1_10 = "ollydbg.exe" ascii //weight: 1
        $x_1_11 = "windbg.exe" ascii //weight: 1
        $x_1_12 = "nav.exe" ascii //weight: 1
        $x_1_13 = "Proxifier.exe" ascii //weight: 1
        $x_1_14 = "Microsoft.Notes.exe" ascii //weight: 1
        $x_1_15 = "Norton Internet Security" ascii //weight: 1
        $x_1_16 = "AVAST Software" ascii //weight: 1
        $x_1_17 = "SELECT * FROM AntiVirusProduct" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_10_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qbot_RA_2147743927_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RA!!Qbot.gen!A"
        threat_id = "2147743927"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "Qbot: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "comet.yahoo.com;.hiro.tv;safebrowsing.google.com;geo.query.yahoo.com;googleusercontent.co" ascii //weight: 1
        $x_1_2 = ";salesforce.com;officeapps.live.com;storage.live.com;messenger.live.com;.twimg.com;" ascii //weight: 1
        $x_1_3 = "api.skype.com;mail.google.com;.bing.com;playtoga.com" ascii //weight: 1
        $x_1_4 = "siteadvisor.com;avgthreatlabs.com;safeweb.norton.com" ascii //weight: 1
        $x_1_5 = "t=%s time=[%02d:%02d:%02d-%02d/%02d/%d]" ascii //weight: 1
        $x_1_6 = "host=[%s:%u] user=[%s] pass=[%s]" ascii //weight: 1
        $x_1_7 = "url=[%s] user=[%s] pass=[%s]" ascii //weight: 1
        $x_1_8 = "avcuf32.dll" ascii //weight: 1
        $x_1_9 = "ollydbg.exe" ascii //weight: 1
        $x_1_10 = "windbg.exe" ascii //weight: 1
        $x_1_11 = "nav.exe" ascii //weight: 1
        $x_1_12 = "Proxifier.exe" ascii //weight: 1
        $x_1_13 = "Microsoft.Notes.exe" ascii //weight: 1
        $x_1_14 = "Norton Internet Security" ascii //weight: 1
        $x_1_15 = "AVAST Software" ascii //weight: 1
        $x_1_16 = "facebook.com/login" ascii //weight: 1
        $x_1_17 = "SELECT * FROM AntiVirusProduct" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (16 of ($x*))
}

rule Trojan_Win32_Qbot_MR_2147744040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.MR!MTB"
        threat_id = "2147744040"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 55 fc 8d 44 02 01 8b 4d 08 03 01 8b 55 08 89 02 8b 45 08 8b 08 83 e9 01 8b 55 08 89 0a 8b e5 5d c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_MS_2147744041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.MS!MTB"
        threat_id = "2147744041"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c2 8b c8 8b d1 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08 5f 5d c3 06 00 8b 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_2147744042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.MT!MTB"
        threat_id = "2147744042"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MT: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec a1 [0-4] a3 [0-4] 55 8b ec 57 [0-4] a1 [0-4] a3 [0-4] 8b [0-5] 8b [0-4] 89 [0-5] a1 [0-4] 2d [0-4] a3}  //weight: 1, accuracy: Low
        $x_1_2 = {8b ff c7 05 [0-8] 01 05 [0-6] 8b 0d [0-4] 8b 15 [0-4] 89 11 33 c0 e9 05 00 a1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_H_2147744169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.H!MSR"
        threat_id = "2147744169"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 0c 8b 4c 24 14 8b 54 24 10 be 00 01 00 00 8b 7c 24 2c 81 f7 ?? ?? ?? ?? 01 f9 89 44 24 08 89 c8 89 54 24 04 99 f7 fe 8b 4c 24 1c 8a 1c 11 0f b6 fb 8b 4c 24 08 01 f9 89 c8 89 14 24 99 f7 fe 8b 4c 24 1c 8a 3c 11 8b 34 24 88 3c 31 88 1c 11 8a 5c 24 1b 80 f3 b2 8a 3c 31 88 5c 24 3f 8b 4c 24 24 8b 74 24 04 8a 1c 31 0f b6 cf 01 f9 81 e1 ff 00 00 00 8b 7c 24 1c 32 1c 0f 8b 4c 24 20 88 1c 31 83 c6 01 69 4c 24 40 9e 47 97 49 89 4c 24 40 8b 4c 24 28 39 ce 8b 0c 24 89 4c 24 14 89 74 24 10 89 54 24 0c 0f 84 36 ff ff ff e9 4d ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_I_2147744170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.I!MSR"
        threat_id = "2147744170"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 d0 89 74 24 38 8b 74 24 24 0f b6 3c 16 89 fb c7 44 24 3c 00 00 00 00 c7 44 24 38 ff 59 e1 5f 8b 74 24 10 01 fe 89 44 24 0c 89 f0 c1 f8 1f c1 e8 18 89 44 24 08 89 f0 89 4c 24 04 8b 4c 24 08 01 c8 25 00 ff ff ff 29 c6 8b 44 24 24 8a 3c 30 88 3c 10 88 1c 30 8b 4c 24 2c 8b 44 24 04 8a 1c 01 8b 44 24 24 0f b6 14 10 01 fa 88 d7 0f b6 d7 8a 3c 10 30 df 8b 54 24 44 66 8b 7c 24 22 66 89 7c 24 34 8b 44 24 38 35 98 59 f9 7b 81 c2 a5 67 da f0 89 44 24 38 8b 44 24 28 8b 4c 24 04 88 3c 08 01 d1 8b 54 24 30 39 d1 8b 44 24 0c 89 44 24 14 89 4c 24 18 89 74 24 1c 0f 84 01 ff ff ff e9 04 ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_DSK_2147744523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.DSK!MTB"
        threat_id = "2147744523"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 0c 0f 66 89 74 24 42 8b 74 24 1c 8b 3c 24 32 0c 3e 8b 74 24 20 8b 7c 24 0c 88 0c 3e}  //weight: 2, accuracy: High
        $x_2_2 = {8a 1c 37 8b 74 24 18 32 1c 0e 8b 4c 24 1c 8b 74 24 04 88 1c 31}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Qbot_PDSK_2147744953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.PDSK!MTB"
        threat_id = "2147744953"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 54 24 2b 8a 74 24 2b 8b 74 24 0c 8a 1c 06 30 f2 88 54 24 2b 8b 44 24 08 88 1c 08}  //weight: 2, accuracy: High
        $x_2_2 = {8a 1c 16 01 c9 88 c7 0f b6 c7 8b 74 24 08 8a 3c 06 89 4c 24 50 30 df 8b 44 24 0c 88 3c 10}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Qbot_VDSK_2147745107_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.VDSK!MTB"
        threat_id = "2147745107"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 44 24 17 34 ff 88 44 24 6b 8a 44 24 3b 8b 4c 24 50 81 f1 9c 28 06 2f 88 44 24 4f 39 4c 24 30}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RD_2147745280_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RD!MTB"
        threat_id = "2147745280"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 04 24 8b 4c 24 ?? 8a 14 01 c7 44 24 14 28 64 af 17 8b 74 24 ?? 88 14 06 83 c0 01 8b 7c 24 ?? 39 f8 89 04 24 74 ?? eb}  //weight: 1, accuracy: Low
        $x_1_2 = {88 04 0e 8b 4c 24 ?? 81 c1 fc 6f 4d bd 66 8b 7c 24 ?? 66 23 7c 24 ?? 66 89 7c 24 ?? 03 4c 24 ?? 89 4c 24 ?? 66 8b 7c 24 ?? 66 81 c7 dc c0 66 89 7c 24 ?? 8b 5c 24 ?? 39 d9 0f 84 ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Qbot_PVD_2147748520_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.PVD!MTB"
        threat_id = "2147748520"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {69 d2 fd 43 03 00 89 15 ?? ?? ?? ?? 81 05 ?? ?? ?? ?? c3 9e 26 00 a0 ?? ?? ?? ?? 30 04 1e 46 3b f7 7c 06 00 8b 15}  //weight: 2, accuracy: Low
        $x_2_2 = {8b d7 b8 b9 5e 01 00 8b ca b8 ff 01 00 00 03 c1 2d ff 01 00 00 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08}  //weight: 2, accuracy: Low
        $x_2_3 = {8a 4c 24 14 8b 84 24 c0 02 00 00 02 d9 81 e3 ff 00 00 00 8a 54 1c 18 8a 1c 07 32 da 88 1c 07 8b 84 24 c4 02 00 00 47 3b f8 0f 8c}  //weight: 2, accuracy: High
        $x_2_4 = {8a 1c 0e 8b 4c 24 1c 8b 3c 24 32 1c 39 c6 44 24 4b e1 8b 4c 24 18 88 1c 39 83 c7 01 8b 4c 24 04 89 4c 24 34}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Qbot_DHA_2147749895_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.DHA!MTB"
        threat_id = "2147749895"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 f8 88 c2 0f b6 c2 66 8b 7c 24 ?? 66 69 ff ?? ?? 66 89 7c 24 ?? 8b 7c 24 ?? 8a 14 07 8b 44 24 ?? 35 ?? ?? ?? ?? 8b 7c 24 ?? 8a 34 0f 30 f2 8b 7c 24 ?? 88 14 0f}  //weight: 1, accuracy: Low
        $x_1_2 = {01 f8 88 c6 0f b6 c6 88 54 24 ?? c7 44 24 38 ?? ?? ?? ?? 8b 7c 24 ?? 8a 14 0f 8b 7c 24 ?? 8a 34 07 30 d6 8b 44 24 ?? 88 34 08}  //weight: 1, accuracy: Low
        $x_1_3 = {8a 04 03 c7 44 24 ?? ?? ?? ?? ?? c7 44 24 ?? ?? ?? ?? ?? 66 8b 5c 24 ?? 66 33 5c 24 ?? 88 44 24 ?? 8b 44 24 ?? 8a 04 38 66 89 5c 24 ?? 8a 64 24 ?? 30 e0 8b 7c 24 ?? 88 04 0f}  //weight: 1, accuracy: Low
        $x_1_4 = {88 04 19 0f b6 14 11 8b 44 24 ?? 35 ?? ?? ?? ?? 01 f2 8b 74 24 ?? 8b 4c 24 ?? 8a 0c 0e 21 fa 8b 7c 24 ?? 8a 2c 17 30 cd 8b 54 24 ?? 8b 74 24 ?? 88 2c 32}  //weight: 1, accuracy: Low
        $x_1_5 = {0f b6 36 03 74 24 ?? 8b 7c 24 ?? 8a 1c 0f 21 c6 32 1c 32 8b 44 24 ?? 35 ?? ?? ?? ?? 8b 4c 24 ?? 89 4c 24 ?? 8b 74 24 ?? 8b 4c 24 ?? 88 1c 31}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Qbot_PVK_2147749965_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.PVK!MTB"
        threat_id = "2147749965"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 c0 fd 43 03 00 83 ec 48 56 a3 05 00 a1}  //weight: 1, accuracy: Low
        $x_1_2 = {30 04 1e 46 3b f7 7c 05 00 e8}  //weight: 1, accuracy: Low
        $x_2_3 = {8a 0c 1f 8b 7c 24 20 32 0c 37 8b 74 24 24 88 0c 1e}  //weight: 2, accuracy: High
        $x_2_4 = {8a 3c 3e 03 4d e8 89 4d e8 30 fb 8b 4d dc 88 1c 39}  //weight: 2, accuracy: High
        $x_2_5 = {8a 54 0d e4 30 14 38 83 f9 14 75 ?? 33 c9 eb}  //weight: 2, accuracy: Low
        $x_2_6 = {8b 45 0c 03 45 fc 8b 4d 08 8a 00 32 04 51 8b 4d 0c 03 4d fc 88 01}  //weight: 2, accuracy: High
        $x_2_7 = {0f b6 c0 33 d8 8b 45 08 03 45 0c 88 18 8b 45 0c 48 89 45 0c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qbot_PVS_2147750716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.PVS!MTB"
        threat_id = "2147750716"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 1c 0f 8b 4c 24 20 8b 74 24 04 32 1c 31 8b 4c 24 1c 88 1c 31}  //weight: 2, accuracy: High
        $x_2_2 = {8a 1c 06 8b 44 24 30 32 1c 08 8b 44 24 2c 88 1c 08}  //weight: 2, accuracy: High
        $x_2_3 = {8b 44 24 28 83 c0 01 8a 4c 24 07 80 f1 ff 88 4c 24 3f}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Qbot_KVD_2147751262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.KVD!MTB"
        threat_id = "2147751262"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 11 8b 45 ?? 03 85 ?? ?? ?? ?? 0f b6 08 33 d1 8b 45 ?? 88 10}  //weight: 2, accuracy: Low
        $x_2_2 = {80 ca dd 88 54 24 ?? 8b 74 24 ?? 88 04 0e 0c 00 8a 44 24 ?? 8b 4c 24 ?? 8a 54 24}  //weight: 2, accuracy: Low
        $x_2_3 = {8b 45 14 03 85 ?? fe ff ff 8b 08 2b 8d ?? fe ff ff 8b 55 14 03 95 ?? fe ff ff 89 0a eb}  //weight: 2, accuracy: Low
        $x_2_4 = {8b c6 f7 f7 8b 44 24 0c 8a 04 02 30 01 46 3b 74 24 ?? 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Qbot_VSD_2147751447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.VSD!MTB"
        threat_id = "2147751447"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 4c 24 14 89 48 04 8b 8c 24 ?? ?? ?? ?? 5f 5e 89 28 5d 33 cc e8 ?? ?? ?? ?? 81 c4 2c 08 00 00}  //weight: 2, accuracy: Low
        $x_2_2 = {89 d8 83 e0 1f 8a 80 ?? ?? ?? ?? 30 04 1e e8 ?? ?? ?? ?? 30 04 1e 43 39 fb 75}  //weight: 2, accuracy: Low
        $x_2_3 = {8b 45 10 03 85 ?? ?? ?? ?? 8a 08 32 8c 15 ?? ?? ?? ?? 8b 55 10 03 95 ?? ?? ?? ?? 88 0a}  //weight: 2, accuracy: Low
        $x_2_4 = {8b 44 24 48 8b 54 24 ?? 8a 1c 0a 32 5c 24 ?? 8b 4c 24 ?? 88 1c 01 8b 44 24 48}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Qbot_DHB_2147751757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.DHB!MTB"
        threat_id = "2147751757"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 d8 89 54 24 ?? 99 f7 fe 88 c8 8a 4c 24 ?? f6 e1 88 44 24}  //weight: 1, accuracy: Low
        $x_1_2 = {01 d8 25 ff 00 00 00 2a 4c 24 ?? 88 4c 24 ?? 8b 5c 24 ?? 32 2c 03 8b 44 24 ?? 88 2c 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_DHC_2147751762_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.DHC!MTB"
        threat_id = "2147751762"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 f7 fe 8b 7c 24 ?? 8a 1c 17 0f b6 fb 89 4c 24 ?? 8b 4c 24 ?? 01 f9 89 c8 89 54 24 ?? 99 f7 fe}  //weight: 1, accuracy: Low
        $x_1_2 = {01 fe 21 de 8b 7c 24 ?? 32 0c 37 8b 74 24 ?? 8b 5c 24 ?? 88 0c 1e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_BS_2147751771_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.BS!MTB"
        threat_id = "2147751771"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 f8 68 50 11 00 00 ff 15 ?? ?? ?? ?? 03 45 ?? 8b 55 ?? 8a 0c 32 88 0c 38 8b 55 ?? 83 c2 01 89 55 ?? e9}  //weight: 1, accuracy: Low
        $x_1_2 = {83 e9 15 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 55 ?? 03 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? a3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_KSP_2147752039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.KSP!MTB"
        threat_id = "2147752039"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 4c 24 12 8a d1 8a c4 c0 e0 04 46 c0 ea 02 0a d0 c0 e1 06 0a 4c 24 13 88 16}  //weight: 2, accuracy: High
        $x_2_2 = {8b f6 33 3d ?? ?? ?? ?? 8b cf b8 04 00 00 00 03 c1 83 e8 04 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08}  //weight: 2, accuracy: Low
        $x_1_3 = {0f b6 c3 03 f8 81 e7 ff 00 00 00 81 3d 64 2b 4f 00 81 0c 00 00 75 0c 00 a1 ?? ?? ?? ?? 0f b6 b8}  //weight: 1, accuracy: Low
        $x_1_4 = {30 04 1f 4f 79 05 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qbot_KPV_2147752041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.KPV!MTB"
        threat_id = "2147752041"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 4d 08 8b 11 81 ea c2 5a 00 00 8b 45 08 89 10 8b e5 5d c3}  //weight: 2, accuracy: High
        $x_2_2 = {8b c7 c1 e9 05 03 0d ?? ?? ?? ?? c1 e0 04 03 05 ?? ?? ?? ?? 33 c8 8d 04 3b 33 c8 8d 9b ?? ?? ?? ?? 2b f1 83 ea 01 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Qbot_MST_2147752385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.MST!MTB"
        threat_id = "2147752385"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d fc 83 c1 04 89 4d fc e8 ?? ?? ?? ?? ba 39 00 00 00 85 d2 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_MMA_2147752663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.MMA!MTB"
        threat_id = "2147752663"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b 0d ?? ?? ?? ?? 83 c1 01 a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 31 0d ?? ?? ?? ?? 8b ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RG_2147752792_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RG!MTB"
        threat_id = "2147752792"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d8 6a 00 e8 ?? ?? ?? ?? 2b d8 8b 45 d8 33 18 89 5d a0 8b 45 a0 8b 55 d8 89 02 8b 45 a8 83 c0 04 89 45 a8 33 c0 89 45 a4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RG_2147752792_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RG!MTB"
        threat_id = "2147752792"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 cb 03 c1 25 ff 00 00 00 0f b6 ?? ?? ?? ?? ?? 30 14 37 83 6c 24 ?? 01 8b 74 24 ?? 85 f6}  //weight: 2, accuracy: Low
        $x_2_2 = {81 e1 ff 00 00 00 8a 91 ?? ?? ?? ?? 0f b6 c2 03 05 ?? ?? ?? ?? 89 0d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RL_2147752842_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RL!MTB"
        threat_id = "2147752842"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 ff 00 00 00 8a 98 ?? ?? ?? ?? 88 ?? ?? ?? ?? ?? 88 99 ?? ?? ?? ?? 0f b6 ?? ?? ?? ?? ?? a3 ?? ?? ?? ?? 0f b6 c3 03 d0 81 e2 ff 00 00 00 8a 8a ?? ?? ?? ?? 30 0c 37 83 6c 24 ?? 01 8b 74 24 ?? 85 f6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RGD_2147752880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RGD!MTB"
        threat_id = "2147752880"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 c9 09 b5 00 00 ?? ?? ?? ?? ?? ?? 81 ea 09 b5 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {83 e9 03 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 2b 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 83 3d ?? ?? ?? ?? 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RGD_2147752880_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RGD!MTB"
        threat_id = "2147752880"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {05 c2 5a 00 00 8b 4d ?? 8b 11 2b d0 8b 45 ?? 89 10 8b e5 5d}  //weight: 2, accuracy: Low
        $x_1_2 = {33 c1 8b ff c7 05 ?? ?? ?? ?? 00 00 00 00 01 05 ?? ?? ?? ?? 8b ff 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 02 5f 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_MMB_2147753348_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.MMB!MTB"
        threat_id = "2147753348"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d2 8b d2 8b d2 8b 0d ?? ?? ?? ?? 83 c1 01 a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 33 c1 8b ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RGS_2147753474_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RGS!MTB"
        threat_id = "2147753474"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 09 88 0c 02 8b 55 ?? 83 c2 01 89 55 ?? eb c9}  //weight: 1, accuracy: Low
        $x_1_2 = {83 e8 15 a3 1c f1 60 00 8b 0d ?? ?? ?? ?? 03 4d ?? 03 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 2b 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? b8 01 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_MX_2147753694_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.MX!MTB"
        threat_id = "2147753694"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ff 8b ff 8b ff 33 c1 8b ff c7 05 ?? ?? ?? ?? 00 00 00 00 01 05 ?? ?? ?? ?? 8b ff a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_MX_2147753694_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.MX!MTB"
        threat_id = "2147753694"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d8 33 d9 8b ff c7 05 ?? ?? ?? ?? 00 00 00 00 01 1d ?? ?? ?? ?? 8b ff a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08}  //weight: 1, accuracy: Low
        $x_1_2 = "16rtu.lAl+oc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_MX_2147753694_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.MX!MTB"
        threat_id = "2147753694"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 ec a3 ?? ?? ?? ?? e8 ?? ?? ?? ?? b9 39 00 00 00 85 c9 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {68 03 5f 00 00 ff 15 ?? ?? ?? ?? 05 c2 5a 00 00 8b 4d ?? 8b 11 2b d0 8b 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_MX_2147753694_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.MX!MTB"
        threat_id = "2147753694"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 11 88 10 8b 45 ?? 83 c0 01 89 45}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c0 04 89 45 ?? ?? ?? e8 ?? ?? ?? ?? 8b 4d ?? 3b 0d ?? ?? ?? ?? 72 ?? ?? ?? ba 18 30 00 00 85 d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_MX_2147753694_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.MX!MTB"
        threat_id = "2147753694"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 11 88 14 30 8b 45 ?? 83 c0 01 89 45}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c0 04 89 45 ?? e8 ?? ?? ?? ?? 8b 4d ?? 3b 0d ?? ?? ?? ?? 72 ?? ?? ?? ba 34 0e 00 00 85 d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_MX_2147753694_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.MX!MTB"
        threat_id = "2147753694"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 08 88 0a 8b 55 ?? 83 c2 01 89 55 ?? eb}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c0 04 89 45 ?? e8 ?? ?? ?? ?? 8b 4d ?? 3b 0d ?? ?? ?? ?? 72 ?? ?? ?? ba 18 30 00 00 85 d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_MX_2147753694_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.MX!MTB"
        threat_id = "2147753694"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 00 88 04 11 8b 4d ?? 83 c1 01 89 4d}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c0 04 89 45 ?? e8 ?? ?? ?? ?? 8b 4d ?? 3b 0d ?? ?? ?? ?? 72 ?? eb ?? ba 9c ad 00 00 85 d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_MX_2147753694_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.MX!MTB"
        threat_id = "2147753694"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba be 15 00 00 ba be 15 00 00 8b ff c7 05 ?? ?? ?? ?? 00 00 00 00 01 05 ?? ?? ?? ?? 8b ff 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 02}  //weight: 1, accuracy: Low
        $x_1_2 = "w234{678o012U4" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_MX_2147753694_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.MX!MTB"
        threat_id = "2147753694"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 00 88 04 11 8b 4d ?? 83 c1 01 89 4d f8}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c0 04 89 45 ?? e8 ?? ?? ?? ?? 8b 4d ?? 3b 0d ?? ?? ?? ?? 72 ?? eb ?? ba 1f de 01 00 85 d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_MX_2147753694_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.MX!MTB"
        threat_id = "2147753694"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 06 88 04 0a 8b 4d ?? 83 c1 01 89 4d}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 ec 89 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 ?? 3b 05 ?? ?? ?? ?? 72 ?? eb ?? b9 39 00 00 00 85 c9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_MX_2147753694_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.MX!MTB"
        threat_id = "2147753694"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 00 88 04 11 8b 4d ?? 83 c1 01 89 4d}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c0 04 89 45 ?? eb ?? e8 ?? ?? ?? ?? 8b 4d ?? 3b 0d ?? ?? ?? ?? 72 ?? eb ?? ba 39 00 00 00 85 d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_MX_2147753694_11
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.MX!MTB"
        threat_id = "2147753694"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 09 88 0c 02 8b 55 ?? 83 c2 01 89 55 ?? eb c7}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 ec 89 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 ?? 3b 05 ?? ?? ?? ?? 72 ?? eb ?? b9 39 00 00 00 85 c9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_MX_2147753694_12
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.MX!MTB"
        threat_id = "2147753694"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5b d3 c0 8a fc 8a e6 d3 cb ff 4d fc 75 ?? 81 [0-5] 33 [0-2] 83 [0-2] 6a 00 89 [0-2] 29 d2 31 da 89 d0 5a aa 49 75}  //weight: 1, accuracy: Low
        $x_1_2 = {89 fa 5f 6a ?? 8f ?? ?? d3 c0 8a fc 8a e6 d3 cb ff ?? ?? 75 ?? 8f ?? ?? 8b ?? ?? 56 83 ?? ?? 31 ?? 83 ?? ?? 31 ?? 5e aa 49 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Qbot_MQ_2147753841_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.MQ!MTB"
        threat_id = "2147753841"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 fc 8a 09 88 0c 02 8b 55 ?? 83 c2 01 89 55 ?? eb}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c1 8b ff c7 05 ?? ?? ?? ?? 00 00 00 00 01 05 ?? ?? ?? ?? 8b ff 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_PVE_2147754085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.PVE!MTB"
        threat_id = "2147754085"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b ff 33 c1 8b ff c7 05 ?? ?? ?? ?? 00 00 00 00 01 05 ?? ?? ?? ?? 8b ff a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08 5f 8b e5 5d c3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_MXI_2147754335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.MXI!MTB"
        threat_id = "2147754335"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 06 88 04 0a 8b 4d ?? 83 c1 01 89 4d}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c0 04 89 45 ?? eb ?? e8 ?? ?? ?? ?? 8b 4d ?? 3b 0d ?? ?? ?? ?? 72 ?? eb ?? ba 39 00 00 00 85 d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_ZA_2147754487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.ZA!MTB"
        threat_id = "2147754487"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d 08 89 31 68 ?? ?? ?? ?? ff 15 ?? ?? ?? 00 05 ?? ?? ?? ?? 8b 55 08 8b 0a 2b c8 8b 55 08 89 0a 5e 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_ZA_2147754487_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.ZA!MTB"
        threat_id = "2147754487"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 f0 68 03 ?? ?? ?? ff 15 ?? ?? ?? ?? 03 f0 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 03 f0 8b 55 08 8b 02 2b c6 8b 4d 08 89 01 5e 8b e5 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_XC_2147754843_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.XC!MTB"
        threat_id = "2147754843"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 30 68 03 5f 00 00 ff 15 ?? ?? ?? ?? 8b f0 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8d 8c 06 ?? ?? ?? ?? 8b 55 08 8b 02 2b c1 8b 4d 08 89 01 5e 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_OD_2147755024_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.OD!MTB"
        threat_id = "2147755024"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 4d e0 8a 55 f9 32 55 f9 88 55 f9 8a 10 8b 45 e4 89 c1 83 c1 01 66 8b 75 fa 66 ?? ?? ?? ?? 66 89 75 fa 89 4d e4 88 10 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_KN_2147755034_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.KN!MTB"
        threat_id = "2147755034"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 5d ff 8a 1c 07 88 1c 01 88 14 07 0f b6 1c 01 0f b6 d2 03 da 81 e3 ff 00 00 80 79 08 4b 81 cb 00 ff ff ff 43 0f b6 d3 8a 14 02 30 16 ff 45 f8 8b 55 f8 3b 55 0c 7c 90}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_PVM_2147755276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.PVM!MTB"
        threat_id = "2147755276"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c0 eb 00 31 0d ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b ff c7 05 ?? ?? ?? ?? 00 00 00 00 01 05 ?? ?? ?? ?? 8b ff 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 02}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_SBR_2147755360_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.SBR!MSR"
        threat_id = "2147755360"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "go-itmriu39047vy5t2874yt9" wide //weight: 5
        $x_1_2 = "PMeqxRBfhD" ascii //weight: 1
        $x_1_3 = "DuplicateIcon" ascii //weight: 1
        $x_1_4 = "InterfacE\\{b196b287-bab4-101a-b69c-00aa00341d07" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_SBR_2147755360_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.SBR!MSR"
        threat_id = "2147755360"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Look at the information window" wide //weight: 1
        $x_1_2 = "reboot Windows and restart" wide //weight: 1
        $x_1_3 = "go-itmriu39047vy5t2874yt9" wide //weight: 1
        $x_1_4 = "encrypted file" wide //weight: 1
        $x_1_5 = "Enter password" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_BX_2147755452_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.BX!MTB"
        threat_id = "2147755452"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 15 f8 15 ?? ?? 03 f0 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 03 f0 8b 55 08 8b 02 2b c6 8b 4d 08 89 01 5e 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_BX_2147755452_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.BX!MTB"
        threat_id = "2147755452"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f0 68 03 ?? ?? ?? ff 15 ?? ?? ?? ?? 8d b4 06 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 03 f0 8b 55 08 8b 02 2b c6 8b 4d 08 89 01 5e 8b e5 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_BX_2147755452_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.BX!MTB"
        threat_id = "2147755452"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d 08 89 01 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b f0 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8d b4 06 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 03 f0 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 03 f0 8b 55 ?? 8b 02 2b c6 8b 4d ?? 89 01 5e 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_KVA_2147755495_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.KVA"
        threat_id = "2147755495"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PMeqxRBfhD" ascii //weight: 1
        $x_1_2 = "DuplicateIcon" ascii //weight: 1
        $x_1_3 = "InterfacE\\{b196b287-bab4-101a-b69c-00aa00341d07" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RAD_2147755667_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RAD!MTB"
        threat_id = "2147755667"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 04 8b 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8d 54 01 ?? 2b 95 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 e8 15 a3 ?? ?? ?? ?? eb ?? 8b 0d ?? ?? ?? ?? 03 8d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 2b 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? b8 01 00 00 00 85 c0 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_TO_2147755810_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.TO!MTB"
        threat_id = "2147755810"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 51 8b 45 0c 89 45 fc 8b 0d ?? ?? ?? ?? 89 4d 08 8b 55 08 8b 02 03 45 fc 8b 4d 08 89 01 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_PO_2147756402_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.PO!MTB"
        threat_id = "2147756402"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 f0 68 03 ?? ?? ?? ff 15 ?? ?? ?? ?? 03 f0 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 03 f0 8b 45 08 8b 08 2b ce 8b 55 08 89 0a 5e 8b e5 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_DSA_2147756526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.DSA!MTB"
        threat_id = "2147756526"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b ff 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 02 5f 5d c3 27 00 a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? ?? ?? 31 0d ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 00 00 00 00 a1 ?? ?? ?? ?? 01 05}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RA_2147756604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RA!MTB"
        threat_id = "2147756604"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 c4 04 8b 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8d 4c 10 ?? 2b 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 83 ea 03 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? ba 87 8a 00 00 85 d2}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RA_2147756604_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RA!MTB"
        threat_id = "2147756604"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 04 a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 8d 44 0a ?? 2b 85 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 0d}  //weight: 1, accuracy: Low
        $x_1_2 = {83 e9 15 89 0d ?? ?? ?? ?? eb ?? 8b 15 ?? ?? ?? ?? 03 95 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? b9 01 00 00 00 85 c9 0f 85}  //weight: 1, accuracy: Low
        $x_2_3 = {83 c4 04 8b 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8d 4c 10 ?? 2b 4d ?? 03 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 83 ea 15 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 45 ?? 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? ba 01 00 00 00 85 d2 0f 85}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qbot_AZ_2147756877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.AZ!MTB"
        threat_id = "2147756877"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 f0 68 03 ?? ?? ?? ff 15 ?? ?? ?? ?? 03 f0 8b 4d 08 8b 11 2b d6 8b 45 08 89 10 5e 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_BB_2147756896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.BB!MTB"
        threat_id = "2147756896"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DllRegisterServer" ascii //weight: 1
        $x_1_2 = "BXJbTZedX" ascii //weight: 1
        $x_1_3 = "BZ5dWj" ascii //weight: 1
        $x_1_4 = "BnS3Z9k" ascii //weight: 1
        $x_1_5 = "CMTjwVe" ascii //weight: 1
        $x_1_6 = "DWUacQ1gb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_DEA_2147757483_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.DEA!MTB"
        threat_id = "2147757483"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba 82 00 01 00 ba 82 00 01 00 ba 82 00 01 00 ba 82 00 01 00 ba 82 00 01 00 8b ff c7 05 ?? ?? ?? ?? 00 00 00 00 01 1d 00 8b ff a1 ?? ?? ?? ?? 8b 0d 00 89 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_DEC_2147757502_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.DEC!MTB"
        threat_id = "2147757502"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "JHUKrwLYkF" ascii //weight: 1
        $x_1_2 = "NYuwntyVXI" ascii //weight: 1
        $x_1_3 = "KBvKfrRMVg" ascii //weight: 1
        $x_1_4 = "XTOjGoQePg" ascii //weight: 1
        $x_1_5 = "DyyWWuwMN" ascii //weight: 1
        $x_1_6 = "lGdzoUpNLQ" ascii //weight: 1
        $x_1_7 = "HFiwxtOoWx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Qbot_AV_2147757599_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.AV!MSR"
        threat_id = "2147757599"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4d 08 8b 11 2b d6 8b 45 08 89 10 5e 8b e5 5d c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_AV_2147757599_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.AV!MSR"
        threat_id = "2147757599"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 08 8b ?? 8b ?? fc 8d 94 01 c2 5a 00 00 8b 45 08 89 10}  //weight: 1, accuracy: Low
        $x_1_2 = "pdf2djvu 0.7.14 (DjVuLibre 3.5.25, poppler 0.18.4, GNOME XSLT 1.1.26, GNOME XML 2.7.8)" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_DSB_2147757720_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.DSB!MTB"
        threat_id = "2147757720"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 0c 31 8a 6c 24 27 80 f5 e1 88 6c 24 4d 8b 74 24 1c 32 0c 16 66 8b 74 24 3e 8b 54 24 20 8b 5c 24 08 88 0c 1a}  //weight: 1, accuracy: High
        $x_1_2 = {8a 08 8b 44 24 20 89 44 24 50 8a 54 24 2b 8b 74 24 44 30 d1 31 ff 89 7c 24 50 8b 5c 24 4c 8b 44 24 18 88 0c 30}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Qbot_DSC_2147757721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.DSC!MTB"
        threat_id = "2147757721"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 1c 37 8b 75 d4 32 1c 0e 8b 4d d8 8b 75 c4 88 1c 31 83 c6 01 8b 4d e0 39 ce 8b 4d c0 89 75 cc 89 4d c8 89 55 d0 0f 84}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_DSD_2147757722_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.DSD!MTB"
        threat_id = "2147757722"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 2c 3b 30 cd c6 44 24 37 41 8b 7c 24 28 88 2c 17 8b 44 24 38 35 d7 cf c7 0e 89 44 24 38 83 c2 01 8b 44 24 30 39 c2 8b 04 24 89 54 24 18 89 44 24 14 89 74 24 1c 0f 84}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_DED_2147757736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.DED!MTB"
        threat_id = "2147757736"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 44 24 23 8b 4c 24 1c 88 01 8b 4c 24 14 41 31 d2 89 54 24 34 89 54 24 30 89 4c 24 18 8b 54 24 0c 39 d1 74 ?? eb ?? 8b 44 24 24 35 ?? ?? ?? ?? 89 44 24 18 8b 44 24 30 8b 4c 24 34 05 ?? ?? ?? ?? 83 d1 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_DEE_2147758016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.DEE!MTB"
        threat_id = "2147758016"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PNuSgGWPVP" ascii //weight: 1
        $x_1_2 = "MqxBTWWMBf" ascii //weight: 1
        $x_1_3 = "CJHsSOmVAg" ascii //weight: 1
        $x_1_4 = "VgVKPmTgWi" ascii //weight: 1
        $x_1_5 = "MQDfoZaFQw" ascii //weight: 1
        $x_1_6 = "cHdCvNcpom" ascii //weight: 1
        $x_1_7 = "LypsvMDoqN" ascii //weight: 1
        $x_1_8 = "LxJbAYhdYo" ascii //weight: 1
        $x_1_9 = "SbHbSTvJPA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Qbot_DEF_2147758040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.DEF!MTB"
        threat_id = "2147758040"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b c8 8b d1 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d 00 89 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_DEG_2147758122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.DEG!MTB"
        threat_id = "2147758122"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "zMCJqAlYAR" ascii //weight: 1
        $x_1_2 = "uHOMqTQxMJ" ascii //weight: 1
        $x_1_3 = "FzJSKRQPbl" ascii //weight: 1
        $x_1_4 = "SJnxYiVlmv" ascii //weight: 1
        $x_1_5 = "TOgUHhiwEY" ascii //weight: 1
        $x_1_6 = "uVGUbWbziq" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Qbot_DEH_2147758253_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.DEH!MTB"
        threat_id = "2147758253"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 f9 81 e1 ff 00 00 00 8b 7c 24 34 8a 1c 0f 8b 4c 24 2c 81 e9 ?? ?? ?? ?? 8b 7c 24 28 89 0c 24 8b 4c 24 0c 8a 3c 0f 8b 0c 24 89 4c 24 48 30 fb 8b 4c 24 24 8b 7c 24 0c 88 1c 39}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_DEH_2147758253_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.DEH!MTB"
        threat_id = "2147758253"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f af ca 89 4c 24 1c 8b 4c 24 14 8a 1c 01 8b 74 24 10 88 1c 06 8b 7c 24 1c 81 f7 [0-8] 89 7c 24 1c 31 ff b9 ?? ?? ?? ?? 8b 54 24 08 29 d1 8b 54 24 0c 19 d7 89 7c 24 24 89 4c 24 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_DEH_2147758253_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.DEH!MTB"
        threat_id = "2147758253"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HRrkiWflou" ascii //weight: 1
        $x_1_2 = "VGAvvAswhs" ascii //weight: 1
        $x_1_3 = "GmZZFypmFO" ascii //weight: 1
        $x_1_4 = "bLMFxw MvB" ascii //weight: 1
        $x_1_5 = "EYjPOZRJQx" ascii //weight: 1
        $x_1_6 = "EVfhiHdCxB" ascii //weight: 1
        $x_1_7 = "CzzkVaqpUE" ascii //weight: 1
        $x_1_8 = "dKqeVNdJcb" ascii //weight: 1
        $x_1_9 = "UHWTIUxGdx" ascii //weight: 1
        $x_1_10 = "MbWCzSISkr" ascii //weight: 1
        $x_1_11 = "xJsEFCTyEd" ascii //weight: 1
        $x_1_12 = "uUSXJcISOt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Qbot_B_2147758343_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.B!MTB"
        threat_id = "2147758343"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 08 5f 5d c3 40 00 a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? ?? ?? 31 0d ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 00 00 00 00 a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? 8b ff a1}  //weight: 2, accuracy: Low
        $x_2_2 = {89 08 5f 5b 5d c3 40 00 8b ff c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 01 05 ?? ?? ?? ?? 8b ff a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08 00 02 a1 ?? ?? ?? ?? 31 0d ?? ?? ?? ?? a1}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Qbot_FC_2147759894_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.FC!MTB"
        threat_id = "2147759894"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 57 a1 ?? ?? ?? 00 a3 ?? ?? ?? 00 8b 0d ?? ?? ?? 00 89 0d ?? ?? ?? 00 8b 15 ?? ?? ?? 00 8b 02 a3 ?? ?? ?? 00 8b 0d ?? ?? ?? 00 81 e9 ?? ?? ?? 00 89 0d ?? ?? ?? 00 8b 0d ?? ?? ?? 00 81 c1 ?? ?? ?? 00 a1 ?? ?? ?? 00 a3 ?? ?? ?? 00 a1 ?? ?? ?? 00 a3 ?? ?? ?? 00 31 0d ?? ?? ?? 00 c7 05 ?? ?? ?? 00 00 00 00 00 a1 ?? ?? ?? 00 01 05 ?? ?? ?? 00 [0-5] 8b 15 ?? ?? ?? 00 a1 ?? ?? ?? 00 89 02 5f 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {03 f0 8b 4d ?? 03 31 8b 55 ?? 89 32 5e 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_DEI_2147759915_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.DEI!MTB"
        threat_id = "2147759915"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 44 24 5c 8b 4c 24 24 8a 14 01 8a 74 24 3f 8b 44 24 1c 89 44 24 74 30 f2 8b 74 24 50 66 c7 44 24 66 71 cf 8b 7c 24 2c 88 14 37}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_DEJ_2147760366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.DEJ!MTB"
        threat_id = "2147760366"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tj8uh5nt9uy23g4b8tuyg23tryg7yq" ascii //weight: 1
        $x_1_2 = "jRoYWilqzE" ascii //weight: 1
        $x_1_3 = "ElfqFbyMFr" ascii //weight: 1
        $x_1_4 = "IelEENYnXN" ascii //weight: 1
        $x_1_5 = "zMCJqAlYAR" ascii //weight: 1
        $x_1_6 = "uHOMqTQxMJ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Qbot_FE_2147760561_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.FE!MTB"
        threat_id = "2147760561"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 89 10 b9 6e 00 00 00 8b 15 ?? ?? ?? ?? 66 89 4a 02 b8 74 00 00 00 20 00 ba 69 00 00 00 a1 ?? ?? ?? ?? 66 89 10 b9 6e 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {03 f0 8b 4d 08 8b 11 2b d6 8b 45 08 89 10 5e 8b e5 5d c3}  //weight: 1, accuracy: High
        $x_1_3 = {8b d8 33 d9 8b ff c7 05 ?? ?? ?? ?? 00 00 00 00 01 1d ?? ?? ?? ?? 8b ff a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_DSE_2147760816_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.DSE!MTB"
        threat_id = "2147760816"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 ff 15 ?? ?? ?? ?? 05 c2 5a 00 00 8b 4d ?? 8b 11 2b d0 8b 45 ?? 89 10 0a 00 8b 45 ?? 89 10 68}  //weight: 1, accuracy: Low
        $x_1_2 = {8b d8 33 d9 8b ff c7 05 ?? ?? ?? ?? 00 00 00 00 01 1d ?? ?? ?? ?? 8b ff a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08 5f 5b 5d c3 05 00 a1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Qbot_DA_2147761214_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.DA!MTB"
        threat_id = "2147761214"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "out.dll" ascii //weight: 1
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
        $x_1_3 = "DllUnregisterServer" ascii //weight: 1
        $x_1_4 = "foremisgiving" ascii //weight: 1
        $x_1_5 = "parturience" ascii //weight: 1
        $x_1_6 = "pimelitis" ascii //weight: 1
        $x_1_7 = "portamento" ascii //weight: 1
        $x_1_8 = "thetically" ascii //weight: 1
        $x_1_9 = "feltmonger" ascii //weight: 1
        $x_1_10 = "athyridae" ascii //weight: 1
        $x_1_11 = "jumana" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_DA_2147761214_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.DA!MTB"
        threat_id = "2147761214"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\GoneWinter\\TrackState\\Mapheat\\sectionHeard" ascii //weight: 1
        $x_1_2 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_3 = "_Repeatbroke" ascii //weight: 1
        $x_1_4 = "_Industrystick" ascii //weight: 1
        $x_1_5 = "VirtualAlloc" ascii //weight: 1
        $x_1_6 = "GetFileType" ascii //weight: 1
        $x_1_7 = "CreateFileA" ascii //weight: 1
        $x_1_8 = "SetEndOfFile" ascii //weight: 1
        $x_1_9 = "WriteFile" ascii //weight: 1
        $x_1_10 = "made.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_DSF_2147761216_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.DSF!MTB"
        threat_id = "2147761216"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f0 33 f1 8b ff c7 05 ?? ?? ?? ?? 00 00 00 00 01 35 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08 5f 5e 5d c3 05 00 a1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_ARA_2147761831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.ARA!MTB"
        threat_id = "2147761831"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "GoogleRR0onRpassedT" wide //weight: 1
        $x_1_2 = "receivingbrowser.nprovidedagdesktopGerman" wide //weight: 1
        $x_1_3 = "aeCWeboverusingcH" wide //weight: 1
        $x_1_4 = "GoogleinterfaceWebcomickthe" wide //weight: 1
        $x_4_5 = "4p62j34i06j234u06j2u34" ascii //weight: 4
        $x_4_6 = "y4094h9ubh294b6h934v8h98t3h249k8" ascii //weight: 4
        $x_4_7 = {8b 55 fc 8d 84 02 23 28 08 00 8b 4d 08 03 01 8b 55 08 89 02}  //weight: 4, accuracy: High
        $x_4_8 = {8b d8 31 0d ?? ?? ?? ?? 8b ff c7 05 ?? ?? ?? ?? 00 00 00 00 8b 3d 00 01 3d 01 a1 54 4c 45 00 8b 0d 01 89 08}  //weight: 4, accuracy: Low
        $x_4_9 = {8a 08 8b 95 fc fe ff ff 33 c0 8a 84 15 00 ff ff ff 33 c8 8b 55 18 03 95 f4 fd ff ff 88 0a}  //weight: 4, accuracy: High
        $x_4_10 = "}iCGYo8aBO1fVgR~m@MovfkS3yoB70ouCTw92OuyN{lf#3OAHH8~}ojIo" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qbot_DEK_2147762092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.DEK!MTB"
        threat_id = "2147762092"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xASJMVVwJN" ascii //weight: 1
        $x_1_2 = "SeYEyGNOSN" ascii //weight: 1
        $x_1_3 = "rRaJMJtLMc" ascii //weight: 1
        $x_1_4 = "oyOqxINoUo" ascii //weight: 1
        $x_1_5 = "qRptZByjjV" ascii //weight: 1
        $x_1_6 = "eMTssapnEE" ascii //weight: 1
        $x_1_7 = "LiImOtohoZ" ascii //weight: 1
        $x_1_8 = "hItPCLcmjZ" ascii //weight: 1
        $x_1_9 = "xzDVeThfIu" ascii //weight: 1
        $x_1_10 = "qvOVXchTuW" ascii //weight: 1
        $x_1_11 = "baTGWqPRGx" ascii //weight: 1
        $x_1_12 = "hYUQhsXKZO" ascii //weight: 1
        $x_1_13 = "BmasBHqnHG" ascii //weight: 1
        $x_1_14 = "sYozqeWNvW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Qbot_DEL_2147762481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.DEL!MTB"
        threat_id = "2147762481"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 f9 88 cb 0f b6 cb 66 c7 44 24 36 00 00 8b 7c 24 28 8b 44 24 04 8a 1c 07 66 c7 44 24 36 00 00 8b 44 24 20 8a 3c 08 30 df 66 c7 44 24 36 ?? ?? 8b 4c 24 24 8b 44 24 04 88 3c 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_DBM_2147762596_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.DBM!MTB"
        threat_id = "2147762596"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "yiqDzvoOrE" ascii //weight: 1
        $x_1_2 = "bn1Lji3v0b " ascii //weight: 1
        $x_1_3 = "DecRlzQ5U2" ascii //weight: 1
        $x_1_4 = "gTz3JmRUZ16cp" ascii //weight: 1
        $x_1_5 = "RjtL7f3liG8Wm" ascii //weight: 1
        $x_1_6 = "2cwuXgAJvEdwwb1Q" ascii //weight: 1
        $x_1_7 = "vcALnh3rC1mc8OM3iU4" ascii //weight: 1
        $x_1_8 = "eEYySKQ79l71lTE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Qbot_SM_2147763012_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.SM!MTB"
        threat_id = "2147763012"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 f0 8b 45 08 03 30 8b 4d 08 89 31}  //weight: 1, accuracy: High
        $x_1_2 = {03 f0 8b 55 08 8b 02 2b c6 8b 4d 08 89 01 5e 8b e5 5d c3}  //weight: 1, accuracy: High
        $x_1_3 = {33 d9 c7 05 ?? ?? ?? ?? 00 00 00 00 01 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08 5b 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_SN_2147763169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.SN!MTB"
        threat_id = "2147763169"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "46"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "Fiddler.exe;samp1e.exe;sample.exe;runsample.exe;lordpe.exe;regshot.exe;Autoruns.exe;dsniff.exe;VBoxTray.exe;HashMyFiles.exe;" ascii //weight: 10
        $x_10_2 = "ProcessHacker.exe;Procmon.exe;Procmon64.exe;netmon.exe;vmtoolsd.exe;vm3dservice.exe;VGAuthService.exe;pr0c3xp.exe;ProcessHacker" ascii //weight: 10
        $x_10_3 = "CFF Explorer.exe;dumpcap.exe;Wireshark.exe;idaq.exe;idaq64.exe;TPAutoConnect.exe;ResourceHacker.exe;vmacthlp.exe;OLLYDBG.EXE;" ascii //weight: 10
        $x_10_4 = "bds-vision-agent-nai.exe;bds-vision-apis.exe;bds-vision-agent-app.exe;MultiAnalysis_v1.0.294.exe;x32dbg.exe;VBoxTray.exe;VBoxSe" ascii //weight: 10
        $x_1_5 = {8d 0c 10 8d 1c 0f 83 e3 ?? 8a 9b ?? ?? ?? ?? 32 1c 16 42 88 19 3b 55 fc 72 e6}  //weight: 1, accuracy: Low
        $x_1_6 = {50 ff 36 83 e9 05 c6 45 f4 e9 89 4d f5 c7 45 fc 05 00 00 00 ff 15 ?? ?? ?? ?? 85 c0 78 1c}  //weight: 1, accuracy: Low
        $x_1_7 = "ROOT\\CIMV2" ascii //weight: 1
        $x_1_8 = "Win32_Process" ascii //weight: 1
        $x_1_9 = "CommandLine" ascii //weight: 1
        $x_1_10 = "runas" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_SO_2147763387_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.SO!MTB"
        threat_id = "2147763387"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 89 08 c7 80 ?? ?? ?? ?? 01 00 00 00 57 8b 90 ?? ?? ?? ?? 8d 0c 90 8b 71 fc 8b fe c1 ef ?? 33 fe 69 ff ?? ?? ?? ?? 03 fa 89 39 ff 80 ?? ?? ?? ?? 81 b8 ?? ?? ?? ?? ?? ?? 00 00 7c d1 5f 5e c3}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 0c 10 8d 1c 0f 83 e3 ?? 8a 9b ?? ?? ?? ?? 32 1c 16 42 88 19 3b 55 fc 72 e6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_SP_2147763601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.SP!MTB"
        threat_id = "2147763601"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://www.ip-adress.com" ascii //weight: 1
        $x_1_2 = "SELECT * FROM Win32_OperatingSystem" ascii //weight: 1
        $x_1_3 = "SELECT * FROM Win32_Processor" ascii //weight: 1
        $x_1_4 = "SELECT * FROM AntiVirusProduct" ascii //weight: 1
        $x_1_5 = "NewRemoteHost" ascii //weight: 1
        $x_1_6 = "NewExternalPort" ascii //weight: 1
        $x_1_7 = "NewProtocol" ascii //weight: 1
        $x_1_8 = "NewInternalPort" ascii //weight: 1
        $x_1_9 = "NewInternalClient" ascii //weight: 1
        $x_1_10 = "NewEnabled" ascii //weight: 1
        $x_1_11 = "NewLeaseTime" ascii //weight: 1
        $x_1_12 = "NewDescription" ascii //weight: 1
        $x_1_13 = "PortMappingEntry" ascii //weight: 1
        $x_1_14 = "\\\\.\\pipe\\%ssp" ascii //weight: 1
        $x_1_15 = "IP address is: <strong>" ascii //weight: 1
        $x_1_16 = "upnp:rootdevice" ascii //weight: 1
        $x_1_17 = "M-SEARCH * HTTP/1.1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_SK_2147764847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.SK!MSR"
        threat_id = "2147764847"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d2 8b d2 a1 ?? ?? ?? 00 8b d2 8b 0d ?? ?? ?? 00 8b d2 a3 ?? ?? ?? 00 8b c0 a1 ?? ?? ?? 00 a3 ?? ?? ?? 00 a1 ?? ?? ?? 00 8b d8 a1 ?? ?? ?? 00 33 d9 c7 05 ?? ?? ?? 00 ?? ?? ?? 00 01 1d ?? ?? ?? 00 a1 ?? ?? ?? 00 8b 0d ?? ?? ?? 00 89 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_MV_2147771418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.MV!MTB"
        threat_id = "2147771418"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {75 12 46 89 7d e4 31 ff 0b 7d fc 89 f8 8b 7d e4 0f b6 1c 30 89 45 e4 83 e0 00 33 45 f0 83 e2 00 31 c2 8b 45 e4 d3 c2 23 d3 ac 0a c2 88 07 47 ff 4d ec 75 b9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_MW_2147772411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.MW!MTB"
        threat_id = "2147772411"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c1 c7 05 [0-8] 01 05 [0-4] a1 [0-4] 8b 0d [0-4] 89 08 5f 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec a1 [0-4] a3 [0-4] 55 8b ec 57 eb 00 eb 00 eb 00 a1 [0-4] a3 [0-4] 8b 0d [0-4] 8b 11 89 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_A_2147775335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.A!!Qbot.A"
        threat_id = "2147775335"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "Qbot: an internal category used to refer to some threats"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b cb 89 4d fc 25 00 (6a 5a|33 d2) 8b c1 5e f7 f6 8b 45 ?? 8a 04 02 [0-3] 32 04 ?? 74 08 41 3b 4d ?? 72}  //weight: 1, accuracy: Low
        $x_1_2 = {5f 5e 5b c9 c3 2a 00 8b 4d ?? 8b 45 ?? 03 ce 03 c1 33 d2 6a 5a 5b f7 f3 8b 45 ?? 8a 04 02 32 04 37 46 88 01 3b 75 fc 72 de 8b 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RF_2147778437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RF!MTB"
        threat_id = "2147778437"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d 80 0d 00 00 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 31 02 83 05 ?? ?? ?? ?? 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RF_2147778437_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RF!MTB"
        threat_id = "2147778437"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 dc 03 45 b0 03 45 bc 8b 15 ?? ?? ?? ?? 31 02 68 ?? ?? ?? ?? e8 [0-100] 83 45 ?? 04 83 05 ?? ?? ?? ?? 04 8b 45 ?? 3b 45 ?? 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RF_2147778437_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RF!MTB"
        threat_id = "2147778437"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 3b 11 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 68 3b 11 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 ?? 31 18 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68}  //weight: 1, accuracy: Low
        $x_1_2 = {05 8a a5 08 00 03 45 ?? 03 d8 68 3b 11 00 00 6a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RF_2147778437_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RF!MTB"
        threat_id = "2147778437"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 02 8b 45 ?? 05 8a a5 08 00 03 45 ?? 8b 55 ?? 31 02 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 45 ?? 04 83 45 ?? 04 8b 45 ?? 3b 45 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RF_2147778437_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RF!MTB"
        threat_id = "2147778437"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 89 45 ?? c7 45 ?? 8a a5 08 00 8b 45 ?? 3b 45 ?? 73}  //weight: 1, accuracy: Low
        $x_1_2 = {8b d8 8b 45 ?? 03 45 ?? 03 45 ?? 03 d8 e8 ?? ?? ?? ?? 2b d8 a1 ?? ?? ?? ?? 31 18 e8 ?? ?? ?? ?? 8b d8 a1 ?? ?? ?? ?? 83 c0 04 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RF_2147778437_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RF!MTB"
        threat_id = "2147778437"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 8a a5 08 00 03 45 ?? 03 d8 68 cf 0d 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 68 cf 0d 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 68 cf 0d 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 68}  //weight: 1, accuracy: Low
        $x_1_2 = {03 d8 68 cf 0d 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 ?? 31 18 6a 00 e8 ?? ?? ?? ?? 6a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RFA_2147778438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RFA!MTB"
        threat_id = "2147778438"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 8a a5 08 00 03 45 ?? 8b 15 ?? ?? ?? ?? 31 02 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 45 ?? 04 83 05 ?? ?? ?? ?? 04 8b 45 ?? 3b 05 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RFA_2147778438_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RFA!MTB"
        threat_id = "2147778438"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EofYkuy" ascii //weight: 1
        $x_1_2 = "PeidHgjWi" ascii //weight: 1
        $x_1_3 = "UyKXRTTMeS" ascii //weight: 1
        $x_1_4 = "JlMycqC" ascii //weight: 1
        $x_1_5 = "fGFODZzHP" ascii //weight: 1
        $x_1_6 = "iUgbioCE" ascii //weight: 1
        $x_1_7 = "xVjrAwSs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RFB_2147778461_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RFB!MTB"
        threat_id = "2147778461"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 e3 14 00 00 6a 00 e8 ?? ?? ?? ?? 8b d8 a1 ?? ?? ?? ?? 8b 00 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 03 55 ?? 33 c2 03 d8 68 e3 14 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 68 e3 14 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RFB_2147778461_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RFB!MTB"
        threat_id = "2147778461"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DllRegisterServer" ascii //weight: 1
        $x_1_2 = "FonkIkN" ascii //weight: 1
        $x_1_3 = "MqvdEvZv" ascii //weight: 1
        $x_1_4 = "VBFjHxFOxC" ascii //weight: 1
        $x_1_5 = "clExrVqR" ascii //weight: 1
        $x_1_6 = "krBVEuWjdl" ascii //weight: 1
        $x_1_7 = "tgWzBT" ascii //weight: 1
        $x_1_8 = "yMBeGI" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RM_2147778589_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RM!MTB"
        threat_id = "2147778589"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 02 33 c0 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b d8 a1 ?? ?? ?? ?? 83 c0 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RM_2147778589_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RM!MTB"
        threat_id = "2147778589"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 49 0e 00 00 6a 00 e8 ?? ?? ?? ?? 8b d8 a1 ?? ?? ?? ?? 8b 00 8b 55 ?? 03 55 ?? 03 55 ?? 33 c2 03 d8 68 49 0e 00 00 6a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RM_2147778589_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RM!MTB"
        threat_id = "2147778589"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TftvgybGtfvgyb" ascii //weight: 1
        $x_1_2 = "KjinhuDdrft" ascii //weight: 1
        $x_1_3 = "IhunEdfdfg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RM_2147778589_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RM!MTB"
        threat_id = "2147778589"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b a5 08 00 [0-10] 64 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {89 18 33 c0 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RM_2147778589_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RM!MTB"
        threat_id = "2147778589"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 8a a5 08 00 03 45 ?? 8b 15 ?? ?? ?? ?? 31 02 83 45 ?? 04 83 05 ?? ?? ?? ?? 04 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 [0-60] 8b 45 ?? 3b 05 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RM_2147778589_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RM!MTB"
        threat_id = "2147778589"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a a5 08 00 8b 45 ?? 3b 45 ?? 73 ?? 8b 45 ?? 8b 55 ?? 01 02 8b 45 ?? 03 45 ?? 03 45 ?? 8b 55 ?? 31 02 83 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RM_2147778589_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RM!MTB"
        threat_id = "2147778589"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 8a a5 08 00 03 45 ?? 03 d8 68 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 ?? 33 18 68 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 ?? 89 18 83 45 ?? 04 83 45 ?? 04 8b 45 ?? 3b 45 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RM_2147778589_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RM!MTB"
        threat_id = "2147778589"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 8a a5 08 00 03 45 ?? 03 d8 68 ?? ?? ?? ?? 6a ?? e8 ?? ?? ?? ?? 03 d8 8b 45 ?? 33 18 68 ?? ?? ?? ?? 6a ?? e8 ?? ?? ?? ?? 03 d8 8b 45 ?? 89 18 83 45 ?? 04 83 45 ?? 04 8b 45 ?? 3b 45 ?? 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RM_2147778589_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RM!MTB"
        threat_id = "2147778589"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a a5 08 00 [0-10] 01 10 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8a a5 08 00 [0-5] e0 21 09 00}  //weight: 1, accuracy: Low
        $x_10_3 = {01 02 8b 45 ?? 03 45 ?? 03 45 ?? 03 45 ?? 8b 55 ?? 31 02 e8 ?? ?? ?? ?? 8b d8 83 c3 04}  //weight: 10, accuracy: Low
        $x_10_4 = {31 18 6a 00 e8 ?? ?? ?? ?? 8b d8 83 c3 04 6a 00 e8 ?? ?? ?? ?? 2b d8}  //weight: 10, accuracy: Low
        $x_10_5 = {31 18 83 45 [0-5] 04 83 [0-5] 04 8b [0-10] 72 [0-10] 00 10 00 00 8b [0-10] 83 c0 04}  //weight: 10, accuracy: Low
        $x_10_6 = {89 02 83 45 ?? 04 8b [0-2] 83 c0 04 89 45 ?? 8b 45 ?? 3b 45 ?? 72 [0-5] c7 45 ?? 00 10 00 00 [0-10] 83 c0 04}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qbot_RMA_2147778602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RMA!MTB"
        threat_id = "2147778602"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b a5 08 00 c7 05}  //weight: 1, accuracy: High
        $x_1_2 = {89 10 33 c0 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 8b d8 a1 ?? ?? ?? ?? 83 c0 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RMA_2147778602_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RMA!MTB"
        threat_id = "2147778602"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RdrfvtKjhgby" ascii //weight: 1
        $x_1_2 = "OjhnbgWdctfvgyb" ascii //weight: 1
        $x_1_3 = "SdrcftvMnhgby" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RMA_2147778602_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RMA!MTB"
        threat_id = "2147778602"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "JgNnXGdh" ascii //weight: 1
        $x_1_2 = "iqdoeEYOHe" ascii //weight: 1
        $x_1_3 = "isxFBD" ascii //weight: 1
        $x_1_4 = "suEOqjW" ascii //weight: 1
        $x_1_5 = "wDFkv" ascii //weight: 1
        $x_1_6 = "zEXauOfp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RMA_2147778602_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RMA!MTB"
        threat_id = "2147778602"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 02 8b 45 ?? 05 8a a5 08 00 03 45 ?? 8b 55 ?? 31 02 6a ?? e8 ?? ?? ?? ?? 6a ?? e8 ?? ?? ?? ?? 6a ?? e8 ?? ?? ?? ?? 6a ?? e8 ?? ?? ?? ?? 6a ?? e8 ?? ?? ?? ?? 6a ?? e8 ?? ?? ?? ?? 83 45 ?? 04 83 45 ?? 04 8b 45 ?? 3b 45 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RMA_2147778602_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RMA!MTB"
        threat_id = "2147778602"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 8a a5 08 00 03 45 ?? 03 d8 68 8c 12 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 68 8c 12 00 00 6a}  //weight: 1, accuracy: Low
        $x_1_2 = {03 d8 68 8c 12 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 a1 ?? ?? ?? ?? 31 18 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 45 ?? 04 83 05 ?? ?? ?? ?? 04 8b 45 ?? 3b 05 ?? ?? ?? ?? 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RMA_2147778602_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RMA!MTB"
        threat_id = "2147778602"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DllRegisterServer" ascii //weight: 1
        $x_1_2 = "EkPUHyiyBK" ascii //weight: 1
        $x_1_3 = "IyGbZkJU" ascii //weight: 1
        $x_1_4 = "ZzqdNzkgyh" ascii //weight: 1
        $x_1_5 = "vRSfKkzjh" ascii //weight: 1
        $x_1_6 = "mYOyQR" ascii //weight: 1
        $x_1_7 = "yJtuHEtei" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RT_2147778665_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RT!MTB"
        threat_id = "2147778665"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d a2 d1 00 00 03}  //weight: 1, accuracy: High
        $x_1_2 = {31 02 6a 01 e8 ?? ?? ?? ?? 8b d8 83 c3 04 6a 01 e8 ?? ?? ?? ?? 2b d8 01 1d ?? ?? ?? ?? 83 05 ?? ?? ?? ?? 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RT_2147778665_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RT!MTB"
        threat_id = "2147778665"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 18 83 45 ?? 04 8b 45 ?? 83 c0 ?? 89 45 ?? 8b 45 ?? 3b 45 ?? 0f 82 ?? ?? ?? ?? c7 45 ?? 00 10 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RT_2147778665_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RT!MTB"
        threat_id = "2147778665"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a a5 08 00 [0-10] 01 10 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b d8 8b 45 ?? 03 45 ?? 03 45 ?? 03 45 ?? 03 d8 e8 ?? ?? ?? ?? 2b d8 8b 45 ?? 31 18 e8 ?? ?? ?? ?? 8b d8 83 c3 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RT_2147778665_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RT!MTB"
        threat_id = "2147778665"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d8 8b 45 ?? 8b 00 03 45 ?? 03 d8 6a ?? e8 ?? ?? ?? ?? 2b d8 8b 45 ?? 89 18 8b 45 ?? 03 45 ?? 03 45 ?? 8b 55 ?? 31 02 6a ?? e8 ?? ?? ?? ?? 8b d8 83 c3 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RT_2147778665_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RT!MTB"
        threat_id = "2147778665"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a a5 08 00 8b 45 ?? 3b 45 ?? 73 ?? 8b 45 ?? 8b 55 ?? 01 02 68 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 8b 55 ?? 03 55 ?? 03 55 ?? 8b 4d ?? 33 11 03 c2 8b 55 ?? 89 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RT_2147778665_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RT!MTB"
        threat_id = "2147778665"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b d8 8b 45 ?? 03 45 ?? 03 45 ?? 03 d8 e8 ?? ?? ?? ?? 2b d8 a1 ?? ?? ?? ?? 31 18 e8 ?? ?? ?? ?? 8b d8 a1 ?? ?? ?? ?? 83 c0 04 03 d8 e8 ?? ?? ?? ?? 2b d8 89 1d ?? ?? ?? ?? 83 45 ?? 04 8b 45 ?? 3b 45 ?? 0f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RT_2147778665_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RT!MTB"
        threat_id = "2147778665"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 89 45 ?? c7 45 ?? 8a a5 08 00 8b 45 ?? 3b 45 ?? 0f}  //weight: 1, accuracy: Low
        $x_1_2 = {03 d8 68 69 23 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 68 69 23 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 ?? 31 18 6a 00 e8 ?? ?? ?? ?? 6a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RT_2147778665_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RT!MTB"
        threat_id = "2147778665"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AvOp0aSule" ascii //weight: 1
        $x_1_2 = "B6RdLyhUwl" ascii //weight: 1
        $x_1_3 = "Bu8SV7xWMDS" ascii //weight: 1
        $x_1_4 = "CG31U0Asd" ascii //weight: 1
        $x_1_5 = "DQN8aPr" ascii //weight: 1
        $x_1_6 = "Dh3OWUSz4rp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RT_2147778665_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RT!MTB"
        threat_id = "2147778665"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d8 8b 45 ?? 05 8a a5 08 00 03 45 ?? 03 d8 68 ?? ?? ?? ?? 6a ?? e8 ?? ?? ?? ?? 03 d8 68}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 ec 31 18 6a ?? e8 ?? ?? ?? ?? 6a ?? e8 ?? ?? ?? ?? 6a ?? e8 ?? ?? ?? ?? 83 45 ?? 04 83 45 ?? 04 8b 45 ?? 3b 45 ?? 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RW_2147778734_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RW!MTB"
        threat_id = "2147778734"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d 80 0d 00 00 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 31 02 83 05 ?? ?? ?? ?? 04 a1 ?? ?? ?? ?? 83 c0 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RW_2147778734_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RW!MTB"
        threat_id = "2147778734"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 00 8b 55 ?? 03 55 ?? 03 55 ?? 33 c2 03 d8 68 8c 10 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 68 8c 10 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 68 8c 10 00 00 6a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RW_2147778734_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RW!MTB"
        threat_id = "2147778734"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 00 8b 55 ?? 03 55 ?? 03 55 ?? 33 c2 03 d8 68 57 15 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 68 57 15 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 68 57 15 00 00 6a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RW_2147778734_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RW!MTB"
        threat_id = "2147778734"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 5c 0e 00 00 6a 00 e8 ?? ?? ?? ?? 8b d8 a1 ?? ?? ?? ?? 8b 00 8b 15 ?? ?? ?? ?? 03 55 ?? 03 55 ?? 33 c2 03 d8 68 5c 0e 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 68 5c 0e 00 00 6a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RW_2147778734_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RW!MTB"
        threat_id = "2147778734"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d8 8b 45 ?? 05 8a a5 08 00 03 45 ?? 03 d8 68 ?? ?? ?? ?? 6a ?? e8 ?? ?? ?? ?? 03 d8}  //weight: 1, accuracy: Low
        $x_1_2 = {03 d8 8b 45 ?? 31 18 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 45 ?? 04 83 45 ?? 04 8b 45 ?? 3b 45 ?? 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RWA_2147778736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RWA!MTB"
        threat_id = "2147778736"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 8a a5 08 00 03 45 ?? 8b 15 ?? ?? ?? ?? 31 02 a1 ?? ?? ?? ?? 83 c0 04 a3 ?? ?? ?? ?? 83 45 ?? 04 8b 45 ?? 3b 45 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RWA_2147778736_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RWA!MTB"
        threat_id = "2147778736"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 8a a5 08 00 03 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 31 02 6a ?? e8 ?? ?? ?? ?? 6a ?? e8 ?? ?? ?? ?? 6a ?? e8 ?? ?? ?? ?? 6a ?? e8 ?? ?? ?? ?? 6a ?? e8 ?? ?? ?? ?? 6a ?? e8 ?? ?? ?? ?? 83 05 ?? ?? ?? ?? 04 83 05 ?? ?? ?? ?? 04 a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
        $x_1_2 = {81 c2 8a a5 08 00 03 55 ?? 33 c2 03 d8 68 ?? ?? ?? ?? 6a ?? e8 ?? ?? ?? ?? 03 d8 68 ?? ?? ?? ?? 6a ?? e8 ?? ?? ?? ?? 03 d8 68 ?? ?? ?? ?? 6a ?? e8 ?? ?? ?? ?? 03 d8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Qbot_RTH_2147779918_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RTH!MTB"
        threat_id = "2147779918"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 10 8b 45 ?? 05 8a a5 08 00 03 45 ?? 8b 15 ?? ?? ?? ?? 31 02 83 45 ?? 04 83 05 ?? ?? ?? ?? 04 8b 45 ?? 3b 45 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RTH_2147779918_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RTH!MTB"
        threat_id = "2147779918"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b a5 08 00 c7 05 [0-5] 64 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {89 02 33 c0 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RTH_2147779918_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RTH!MTB"
        threat_id = "2147779918"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 8a a5 08 00 03 45 ?? 8b 55 ?? 31 02 6a 00 e8 ?? ?? ?? ?? 8b d8 83 c3 04 6a 00 e8 ?? ?? ?? ?? 2b d8 01 5d ?? 83 45 ?? 04 8b 45 ?? 3b 45 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RTH_2147779918_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RTH!MTB"
        threat_id = "2147779918"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 8a a5 08 00 03 45 ?? 03 d8 68 cf 0d 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 68 cf 0d 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {68 cf 0d 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 ?? 31 18 8d 85 ?? ?? ?? ?? 33 c9 ba 3c 00 00 00 e8 ?? ?? ?? ?? 8d 85 68 ff ff ff 33 c9 ba 3c 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_MY_2147781916_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.MY!MTB"
        threat_id = "2147781916"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 c0 8a fc 8a e6 d3 cb ff [0-4] 57 33 [0-2] 09 ?? 83 [0-2] 09 ?? 5f 81 [0-5] 33 [0-2] 83 [0-2] aa 49 75}  //weight: 1, accuracy: Low
        $x_1_2 = {d3 c0 8a fc 8a e6 d3 cb ff [0-5] 8f [0-2] ff [0-2] 58 81 [0-5] 33 [0-2] 83 [0-2] aa 49 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Qbot_MZ_2147782068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.MZ!MTB"
        threat_id = "2147782068"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 c0 8a fc 8a e6 d3 cb ff [0-4] 6a 00 89 [0-2] 29 ?? 31 ?? 89 ?? 5d 31 ?? 8b ?? ?? 83 ?? ?? aa 49 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_NA_2147782127_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.NA!MTB"
        threat_id = "2147782127"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a c3 2c 09 02 c2 0f [0-2] 8b ?? 2b ?? 0f [0-2] 2b ?? 89 [0-3] 8b [0-3] 89 [0-5] 8b [0-3] 8a e2 80 ec 09 8b 3f 02 e0 3b ce 8a ca 81 [0-5] 2a cb 89 [0-5] 80 [0-2] 02 c1 8b [0-3] 83 [0-4] 89 39 8b [0-5] 8b [0-4] 69 [0-5] 83 [0-4] 0f [0-2] 89 [0-3] 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_NB_2147782308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.NB!MTB"
        threat_id = "2147782308"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {33 55 f0 89 55 f0 8b 45 ec 8b 4d f8 d3 f8 83 f0 04 89 45 ec 8b 55 f4 03 55 08 8b 4d 08 d3 e2 8b 4d 08 d3 fa 8b 4d f8 d3 fa 8b 4d f8 d3 e2 8b 4d 08 d3}  //weight: 10, accuracy: High
        $x_3_2 = "rolliche" ascii //weight: 3
        $x_3_3 = "triobol" ascii //weight: 3
        $x_3_4 = "Dll\\out.pdb" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_NB_2147782308_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.NB!MTB"
        threat_id = "2147782308"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 f2 8d [0-3] 89 [0-5] 8d [0-2] bf [0-4] 2b fe 03 d7 0f [0-6] 03 [0-5] 8b [0-3] 89 [0-5] 8b [0-5] 8d [0-6] 8b [0-2] 0f [0-2] 39 [0-5] 83 [0-4] 8a c2 b3 11 f6 eb 81 [0-5] 02 c1 81 [0-7] 89 [0-5] 89 [0-2] 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_NC_2147782963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.NC!MTB"
        threat_id = "2147782963"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 c3 3d 02 db 81 [0-5] 2a da 89 [0-5] 02 [0-5] 89 [0-6] 83 c5 04 81 [0-7] 8b [0-5] 8b [0-5] 8b [0-5] 8b [0-5] a1 [0-4] 2b c7 3d [0-4] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_ND_2147783387_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.ND!MTB"
        threat_id = "2147783387"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 7c 24 18 81 [0-5] 01 [0-5] 81 [0-7] 8b [0-3] 8b 17 0f [0-6] 2b c8 83 [0-2] 81 [0-5] 89 [0-5] 89 17 83 [0-2] 89 [0-5] 8b [0-5] 83 [0-2] 89 [0-3] 03 d0 ff [0-3] 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RPF_2147796518_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RPF!MTB"
        threat_id = "2147796518"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Plan_Soon" ascii //weight: 1
        $x_1_2 = "Shape_Enter" ascii //weight: 1
        $x_1_3 = "cent.pdb" ascii //weight: 1
        $x_1_4 = "cent.dll" ascii //weight: 1
        $x_1_5 = "Arrangesurprise" ascii //weight: 1
        $x_1_6 = "Count" ascii //weight: 1
        $x_1_7 = "Drawpaper" ascii //weight: 1
        $x_1_8 = "Favorship" ascii //weight: 1
        $x_1_9 = "Gavechick" ascii //weight: 1
        $x_1_10 = "HistoryMoment" ascii //weight: 1
        $x_1_11 = "Hitanimal" ascii //weight: 1
        $x_1_12 = "Standterm" ascii //weight: 1
        $x_1_13 = "VirtualProtectEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RPT_2147797703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RPT!MTB"
        threat_id = "2147797703"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 0d 97 f9 08 10 3b f9 74 25 00 98 90 f9 08 10 8b d3 8b cb 83 e8 02 2b ce 8d b1 10 67 01 00 8d 0c 7a 8d be 40 f8 ff ff 03 f9 83 f8 03 7f d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_KDU_2147797879_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.KDU!MTB"
        threat_id = "2147797879"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a c3 2a c2 83 c1 09 83 ee 02 8d 50 2f 0f b6 c2 2b c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RPV_2147797923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RPV!MTB"
        threat_id = "2147797923"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {a1 00 0f 47 00 8b 15 b0 0e 47 00 01 02 a1 e8 0e 47 00 2d a2 d1 00 00 03 05 00 0f 47 00 a3 f0 0e 47 00 a1 f0 0e 47 00 a3 ec 0e 47 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RPV_2147797923_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RPV!MTB"
        threat_id = "2147797923"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 54 24 10 8d 42 04 02 05 ?? ?? ?? ?? 8b 3d ?? ?? ?? ?? 8d 8e ?? ?? ?? ?? 89 4d 00 83 c5 04 89 0d ?? ?? ?? ?? b1 a7 2a ca 2a 0d ?? ?? ?? ?? 02 c1 83 6c 24 18 01 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_ME_2147812922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.ME!MTB"
        threat_id = "2147812922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {ff 2b d8 89 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 31 02}  //weight: 5, accuracy: Low
        $x_5_2 = {86 c0 7c 50 b3 ca 6b 41 a5 c1 7a 65 b2 d6 08 00 c1 a5 08 56 a8 d7 7c 75 a0 c9 49 6c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_DB_2147813044_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.DB!MTB"
        threat_id = "2147813044"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "out.dll" ascii //weight: 1
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
        $x_1_3 = "DllUnregisterServer" ascii //weight: 1
        $x_1_4 = "referribleness" ascii //weight: 1
        $x_1_5 = "staphylematoma" ascii //weight: 1
        $x_1_6 = "petrolist" ascii //weight: 1
        $x_1_7 = "demicaponier" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_M_2147813139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.M!MTB"
        threat_id = "2147813139"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "InquireSoap" ascii //weight: 3
        $x_3_2 = "inquire_v1" ascii //weight: 3
        $x_3_3 = "ActiveScript" ascii //weight: 3
        $x_3_4 = "GetAcceptExSockaddrs" ascii //weight: 3
        $x_3_5 = "TSOAPAttachment" ascii //weight: 3
        $x_3_6 = "GSOAPDomConv" ascii //weight: 3
        $x_3_7 = "zWebServExp" ascii //weight: 3
        $x_3_8 = {86 c0 7c 50 b3 ca 6b 41 a5 c1 7a 65}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_DC_2147813321_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.DC!MTB"
        threat_id = "2147813321"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "out.dll" ascii //weight: 1
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
        $x_1_3 = "DllUnregisterServer" ascii //weight: 1
        $x_1_4 = "belemnoidea" ascii //weight: 1
        $x_1_5 = "ischioanal" ascii //weight: 1
        $x_1_6 = "overhonestly" ascii //weight: 1
        $x_1_7 = "petalodic" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_DD_2147813373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.DD!MTB"
        threat_id = "2147813373"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "out.dll" ascii //weight: 1
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
        $x_1_3 = "DllUnregisterServer" ascii //weight: 1
        $x_1_4 = "pylethrombophlebitis" ascii //weight: 1
        $x_1_5 = "bactericide" ascii //weight: 1
        $x_1_6 = "delicatesse" ascii //weight: 1
        $x_1_7 = "tossicated" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_DE_2147813549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.DE!MTB"
        threat_id = "2147813549"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "out.dll" ascii //weight: 1
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
        $x_1_3 = "DllUnregisterServer" ascii //weight: 1
        $x_1_4 = "addlepatedness" ascii //weight: 1
        $x_1_5 = "chondrogenous" ascii //weight: 1
        $x_1_6 = "methylnaphthalene" ascii //weight: 1
        $x_1_7 = "spokeswomanship" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_DF_2147813772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.DF!MTB"
        threat_id = "2147813772"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cHIET.dll" ascii //weight: 1
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
        $x_1_3 = "PiSGzfagaNvMr" ascii //weight: 1
        $x_1_4 = "ILniTJdtlhh" ascii //weight: 1
        $x_1_5 = "tAXoXCjNXVUbOz" ascii //weight: 1
        $x_1_6 = "wLJeClmoFX" ascii //weight: 1
        $x_1_7 = "MjmoVbFT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_DG_2147814027_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.DG!MTB"
        threat_id = "2147814027"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "k9pfl.dll" ascii //weight: 1
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
        $x_1_3 = "MifDtzaMhgG" ascii //weight: 1
        $x_1_4 = "ZHxbETopuOI" ascii //weight: 1
        $x_1_5 = "jKuEkhbMkMhYKG" ascii //weight: 1
        $x_1_6 = "gUmamXP" ascii //weight: 1
        $x_1_7 = "EqualRgn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_DH_2147814031_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.DH!MTB"
        threat_id = "2147814031"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DllRegisterServer" ascii //weight: 10
        $x_1_2 = "s8n6a4aa.dll" ascii //weight: 1
        $x_1_3 = "cFNvgIplCBvtemg" ascii //weight: 1
        $x_1_4 = "pgBIGnLmtFXpL" ascii //weight: 1
        $x_1_5 = "HGGvVeUldku" ascii //weight: 1
        $x_1_6 = "vbisfIhaUR" ascii //weight: 1
        $x_1_7 = "Z6yNN34D.lib" ascii //weight: 1
        $x_1_8 = "qqhJsazbzYEL" ascii //weight: 1
        $x_1_9 = "xWpUPVzbOtIHwR" ascii //weight: 1
        $x_1_10 = "yOfVjQotcFjid" ascii //weight: 1
        $x_1_11 = "IatbZpcenkI" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qbot_RTA_2147814264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RTA!MTB"
        threat_id = "2147814264"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 18 6a 01 e8 ?? ?? ?? ?? 8b d8 83 c3 04 6a 01 e8 ?? ?? ?? ?? 2b d8 01 1d ?? ?? ?? ?? 83 05 ?? ?? ?? ?? 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RTA_2147814264_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RTA!MTB"
        threat_id = "2147814264"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 04 89 45 ?? 8b 45 ?? 3b 45 ?? 0f 82 ?? ?? ?? ?? c7 45 ?? 00 10 00 00 8b 45 ?? 03 45 ?? 2b 45 ?? 83 c0 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RTA_2147814264_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RTA!MTB"
        threat_id = "2147814264"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MifDtzaMhgG" ascii //weight: 1
        $x_1_2 = "ZHxbETopuOI" ascii //weight: 1
        $x_1_3 = "gUmamXP" ascii //weight: 1
        $x_1_4 = "jKuEkhbMkMhYKG" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RTB_2147814265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RTB!MTB"
        threat_id = "2147814265"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DllRegisterServer" ascii //weight: 1
        $x_1_2 = "FxeSRkVqoZOdcs" ascii //weight: 1
        $x_1_3 = "OLXgvfndM" ascii //weight: 1
        $x_1_4 = "UvDOosQaiPp" ascii //weight: 1
        $x_1_5 = "YYMoZeejtiWU" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_QR_2147815773_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.QR!MTB"
        threat_id = "2147815773"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AebOqOfayA" ascii //weight: 1
        $x_1_2 = "BGGEyuK" ascii //weight: 1
        $x_1_3 = "BludKRR" ascii //weight: 1
        $x_1_4 = "DllRegisterServer" ascii //weight: 1
        $x_1_5 = "FboQX" ascii //weight: 1
        $x_1_6 = "HwzUdbyjin" ascii //weight: 1
        $x_1_7 = "SDzgxnhKoD" ascii //weight: 1
        $x_1_8 = "fOzZUxe" ascii //weight: 1
        $x_1_9 = "fwUUwqtqUi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RRR_2147815931_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RRR!MTB"
        threat_id = "2147815931"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e8 2c 03 45 ?? 89 45 ?? 8b 45 ?? 03 45 ?? 8b 55 ?? 31 02 6a 00 e8 ?? ?? ?? ?? 8b 5d ?? 83 c3 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_PAE_2147817583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.PAE!MTB"
        threat_id = "2147817583"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 a8 03 45 ac 48 89 45 a4 8b 45 a8 8b 55 d8 01 02 8b 45 c4 03 45 a4 89 45 a0 8b 45 d8 8b 00 33 45 a0 89 45 a0 8b 45 a0 8b 55 d8 89 02 33 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_PAE_2147817583_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.PAE!MTB"
        threat_id = "2147817583"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {80 45 f9 2a c6 45 fa 00 66 3b db 74 00 bb 41 77 26 07 83 c3 0b eb 53 80 45 f4 4c c6 45 f5 55 66 3b e4 74 19 83 ec 18 c6 45 f4 29 66 3b e4 74 e7 80 45 f7 46 c6 45 f8 02 66 3b d2 74 20 80 45 f5}  //weight: 2, accuracy: High
        $x_1_2 = "DF9AdmP" ascii //weight: 1
        $x_1_3 = "F7MIlc7kJnm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_EN_2147817739_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.EN!MTB"
        threat_id = "2147817739"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "out.dll" ascii //weight: 1
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
        $x_1_3 = "DllUnregisterServer" ascii //weight: 1
        $x_1_4 = "KJI441A0aVBAyLka92P" ascii //weight: 1
        $x_1_5 = "EcTG3NTCiwi1fTGK6H4" ascii //weight: 1
        $x_1_6 = "ImTobIOb9L6JrqCFEN" ascii //weight: 1
        $x_1_7 = "YpvJom3jmu90dHBWq" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_PAF_2147817741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.PAF!MTB"
        threat_id = "2147817741"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2b d8 8b 45 d8 89 18 8b 45 c4 03 45 a4 89 45 a0 8b 45 d8 8b 00 33 45 a0 89 45 a0 8b 45 a0 8b 55 d8 89 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_PAF_2147817741_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.PAF!MTB"
        threat_id = "2147817741"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c2 89 45 f0 0f b6 0d ?? ?? ?? ?? 33 4d f0 89 4d f0 0f b6 15 ?? ?? ?? ?? 33 55 f0 89 55 f0 0f b6 05 ?? ?? ?? ?? 33 45 f0 89 45 f0 0f b6 0d ?? ?? ?? ?? 8b 55 f0 2b d1 89 55 f0 0f b6 05 ?? ?? ?? ?? 33 45 f0 89 45 f0 8b 0d ?? ?? ?? ?? 03 4d ec 8a 55 f0 88 11}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_PAF_2147817741_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.PAF!MTB"
        threat_id = "2147817741"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWAREMicrosoft" wide //weight: 1
        $x_1_2 = "RfEUvvLCfEjjqfxBkOeTnHaMVWICzWpHIvgsFNN" ascii //weight: 1
        $x_1_3 = "IucNrghmHGSzbIffyqdYdRyQFfZlQigeJReA" ascii //weight: 1
        $x_1_4 = "YOpMsscDPTAifUJIGqCACbDDfZqusefvPee" ascii //weight: 1
        $x_1_5 = "aziethane" ascii //weight: 1
        $x_1_6 = "bigheartedness" ascii //weight: 1
        $x_1_7 = "wonning" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_ES_2147818074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.ES!MTB"
        threat_id = "2147818074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "out.dll" ascii //weight: 1
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
        $x_1_3 = "DllUnregisterServer" ascii //weight: 1
        $x_1_4 = "fsdfsd.exe" ascii //weight: 1
        $x_1_5 = "sdfsdfsd" ascii //weight: 1
        $x_1_6 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_7 = "FileTimeToLocalFileTime" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_AN_2147818115_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.AN!MTB"
        threat_id = "2147818115"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ARyZiiOrmfl" ascii //weight: 2
        $x_2_2 = "Arw3qg" ascii //weight: 2
        $x_2_3 = "BMeGjTK" ascii //weight: 2
        $x_2_4 = "BRWxGWYcWi3" ascii //weight: 2
        $x_2_5 = "BdTh8uKD" ascii //weight: 2
        $x_2_6 = "DllRegisterServer" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_AN_2147818115_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.AN!MTB"
        threat_id = "2147818115"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 58 35 35 35 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 55 7a 6d 61 5f 73 74 72 65 61 6d 5f 66 6c 61 67 73 5f 63 6f 6d 70 61 72 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 55 7a 6d 61 5f 73 74 72 65 61 6d 5f 68 65 61 64 65 72 5f 65 6e 63 6f 64 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 55 7a 6d 61 5f 69 6e 64 65 78 5f 75 6e 63 6f 6d 70 72 65 73 73 65 64 5f 73 69 7a 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 55 7a 6d 61 5f 70 68 79 73 6d 65 6d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_AM_2147818226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.AM!MTB"
        threat_id = "2147818226"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ALR53sdSW" ascii //weight: 2
        $x_2_2 = "AMiHQ7" ascii //weight: 2
        $x_2_3 = "BVbIVc4g2" ascii //weight: 2
        $x_2_4 = "BZ8WkC" ascii //weight: 2
        $x_2_5 = "Bf3P5E6" ascii //weight: 2
        $x_2_6 = "CNy5sq3LMre" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_AM_2147818226_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.AM!MTB"
        threat_id = "2147818226"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DllRegisterServer" ascii //weight: 1
        $x_1_2 = "DmECMHZT" ascii //weight: 1
        $x_1_3 = "IMkSE2Goi" ascii //weight: 1
        $x_1_4 = "NL5u03" ascii //weight: 1
        $x_1_5 = "PI9PVF3zLW5" ascii //weight: 1
        $x_1_6 = "TDe5ne0VV9" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_AM_2147818226_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.AM!MTB"
        threat_id = "2147818226"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DSijzCfYwEx" ascii //weight: 1
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
        $x_1_3 = "FCZEr8YEz7" ascii //weight: 1
        $x_1_4 = "GgkAWHo5OLp" ascii //weight: 1
        $x_1_5 = "KRiy1Ybln6o" ascii //weight: 1
        $x_1_6 = "S9NAg9C" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_AM_2147818226_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.AM!MTB"
        threat_id = "2147818226"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b c2 89 45 ?? 0f b6 0d ?? ?? ?? ?? 03 4d ?? 89 4d ?? 0f b6 15 ?? ?? ?? ?? 8b 45 ?? 2b c2 89 45 ?? 0f b6 0d ?? ?? ?? ?? 8b 55 ?? 2b d1 89 55 ?? 0f b6 05 ?? ?? ?? ?? 03 45 ?? 89 45 ?? 0f b6 0d ?? ?? ?? ?? 8b 55 ?? 2b d1 89 55 ?? 0f b6 05 ?? ?? ?? ?? 33 45 ?? 89 45}  //weight: 2, accuracy: Low
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_FQ_2147818255_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.FQ!MTB"
        threat_id = "2147818255"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ai9EwaR6GhN" ascii //weight: 1
        $x_1_2 = "BUoerTe" ascii //weight: 1
        $x_1_3 = "BXvaR5AI" ascii //weight: 1
        $x_1_4 = "Bjc2uQ1Qi1A" ascii //weight: 1
        $x_1_5 = "BuP0BTX" ascii //weight: 1
        $x_1_6 = "BvOKhJ1YbAd" ascii //weight: 1
        $x_1_7 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RPM_2147819275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RPM!MTB"
        threat_id = "2147819275"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2b d8 89 5d a4 8b 45 a8 8b 55 d8 01 02 8b 45 c4 03 45 a4 8b 55 d8 33 02 89 45 a0 8b 45 a0 8b 55 d8 89 02 33 c0 89 45 a4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_PAC_2147819912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.PAC!MTB"
        threat_id = "2147819912"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d8 8b 45 d8 8b 00 03 45 a8 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 [0-7] e8 ?? ?? ?? ?? 8b d8 8b 45 c4 03 45 a4 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 8b 45 d8 33 18 89 5d a0 8b 45 a0 8b 55 d8 89 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_PAG_2147821198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.PAG!MTB"
        threat_id = "2147821198"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 8b c6 f7 75 f4 8b 45 08 8a 04 02 32 04 0e 88 04 37 46 83 eb ?? 75 e7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_PAI_2147823771_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.PAI!MTB"
        threat_id = "2147823771"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a d6 0f b6 87 ?? ?? ?? ?? 6b c0 ?? d2 ea 22 d0 8b c6 46 85 c0 74 0f 8b 4f 1c 8a 04 0b 02 c0 0a c2 88 04 0b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_PAJ_2147827782_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.PAJ!MTB"
        threat_id = "2147827782"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 3c 31 88 1c 11 0f b6 0c 31 01 f9 81 ?? ff 00 00 00 8b 7c 24 ?? 8b 74 24 ?? 8a 1c 37 8b 74 24 ?? 32 1c 0e 8b 4c 24 ?? 8b 74 24 ?? 88 1c 31}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_PAL_2147831473_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.PAL!MTB"
        threat_id = "2147831473"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d0 8b 45 ?? 33 10 89 55 ?? 8b 45 ?? 8b 55 ?? 89 02 33 c0 89 45 a4 8b 45 ?? 83 c0 04 03 45 ?? 89 45 a8 6a 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_PAL_2147831473_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.PAL!MTB"
        threat_id = "2147831473"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 04 8b 4d ?? 8a 14 02 32 14 19 8b 45 ?? 88 14 03 33 d2 8b 45 ?? c7 85 [0-8] 8b 48 ?? 8b 85 d4 00 00 00 05 12 b5 ff ff 03 c1 f7 75 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_PAM_2147831474_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.PAM!MTB"
        threat_id = "2147831474"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 0c 03 8b 46 ?? 2a 4c 24 ?? 03 c3 32 4c 24 ?? 88 0c 38 8b 4c 24 ?? 83 f9 ?? 0f 84 ?? ?? ?? ?? 8b 56 1c b0 01 03 d3 d2 e0 fe c8 8a 14 3a 22 d0 8b c1 88 54 24}  //weight: 2, accuracy: Low
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
        $x_1_3 = "ANdF226J4q" ascii //weight: 1
        $x_1_4 = "IPa579" ascii //weight: 1
        $x_1_5 = "OYRCC43y7" ascii //weight: 1
        $x_6_6 = {40 89 86 b4 01 00 00 8b 86 ?? ?? ?? ?? 8b 56 ?? 8b 4e ?? 8a 14 02 32 14 0b 8b 46 ?? 88 14 03 33 d2 8b 86 ?? ?? ?? ?? 8b 48 0c 8b 86 ?? ?? ?? ?? 05 ?? ?? ?? ?? 03 c1 f7 76}  //weight: 6, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_6_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qbot_PAN_2147831548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.PAN!MTB"
        threat_id = "2147831548"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 46 1c 2a 4c 24 ?? 03 c3 32 4c 24 ?? 83 7c 24 34 ?? 88 0c ?? 0f 84 ?? ?? ?? ?? 8b 56 1c b0 01 8b 4c 24 34 03 d3 d2 e0 fe c8 8a 14 3a}  //weight: 10, accuracy: Low
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
        $x_1_3 = "ANdF226J4q" ascii //weight: 1
        $x_1_4 = "IPa579" ascii //weight: 1
        $x_1_5 = "OYRCC43y7" ascii //weight: 1
        $x_1_6 = "QEY0Wo7" ascii //weight: 1
        $x_1_7 = "PqxLTivB" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qbot_PAO_2147831640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.PAO!MTB"
        threat_id = "2147831640"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 45 a4 8b 45 ?? 8b 55 ?? 01 02 8b 45 c4 03 45 a4 89 45 a0 6a 00 e8 ?? ?? ?? ?? 8b 55 a0 2b d0 8b 45 ?? 33 10 89 55 ?? 8b 45 ?? 8b 55 ?? 89 02 8b 45 a8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_PAP_2147831777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.PAP!MTB"
        threat_id = "2147831777"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 3b 2a cf 62 70 ae 5c b8 f3 f6 2b 9d b7 d1 03 77 9e 30 32 69 3e 33 38 fd fb f0 e8 a2 db e0 d0 14 2e ab 19 7d 74 d1 9f 3c c5 92 44 a1 67 84 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_PAQ_2147831825_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.PAQ!MTB"
        threat_id = "2147831825"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {67 5a 23 81 cf 1e fe 4d e7 d5 8f 2f 9d 29 ac 88 7b e9 8a}  //weight: 1, accuracy: High
        $x_1_2 = {24 60 7f c8 81 4a bb 1f a9 94 c3 73 c2 76 c9 e5 0b 9d f3}  //weight: 1, accuracy: High
        $x_1_3 = {1b b9 7e 04 60 46 73 d0 ec c3 02 79 1a d4 95 86 97 b9 20 bc 88 09 3f 77 88 ec b9 e0 2e}  //weight: 1, accuracy: High
        $x_1_4 = {48 c0 0d 70 05 2b 21 bf 83 b7 27 25 49 ad e6 d1 d8 ee 16 88 d4 64 4c 05 e9 c2 dc 98 4b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_PAR_2147831930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.PAR!MTB"
        threat_id = "2147831930"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 0c 2b 8a 14 28 2a 54 24 ?? 8b 47 ?? 32 54 24 ?? 83 7c 24 ?? ?? 88 14 01 0f 84 ?? ?? ?? ?? 8b 47 ?? 8d 34 2b 8b 4c 24 ?? b2 01 d2 e2 fe ca 8a 2c 06 8b 44 24 ?? 22 ea 88}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_PAS_2147833184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.PAS!MTB"
        threat_id = "2147833184"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c2 89 45 a0 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 03 45 ?? 8b 55 ?? 33 02 89 45 ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 03 45 ?? 8b 55 ?? 89 02 8b 45 ?? 83 c0 04 89 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_PAT_2147833549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.PAT!MTB"
        threat_id = "2147833549"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d8 8b 45 d8 33 18 89 5d ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b d8 03 5d a0 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 03 d8 8b 45 d8 89 18 8b 45 a8 83 c0 04 89 45 a8 33 c0 89 45 a4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_PAU_2147833575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.PAU!MTB"
        threat_id = "2147833575"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 f7 7d dc 8b 45 10 0f b6 14 10 03 ca 88 4d fe 0f b6 45 ?? 8b 4d 08 03 4d ?? 0f b6 11 33 d0 8b 45 08 03 45 f8 88 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_AG_2147833604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.AG!MSR"
        threat_id = "2147833604"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 a8 03 45 ac 48 89 45 a4 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b d8 8b 45 d8 8b 00 03 45 a8 03 d8 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 03 d8 8b 45 d8 89 18 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 55 c4 03 55 a4 03 c2 89 45 a0 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b d8 03 5d a0 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 03 d8 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 03 d8 8b 45 d8 33 18}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_AG_2147833604_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.AG!MSR"
        threat_id = "2147833604"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DllRegisterServer" ascii //weight: 1
        $x_1_2 = "DllUnregisterServer" ascii //weight: 1
        $x_1_3 = "buildable" ascii //weight: 1
        $x_1_4 = "euornithic" ascii //weight: 1
        $x_1_5 = "paranitrosophenol" ascii //weight: 1
        $x_1_6 = "photosynthetically" ascii //weight: 1
        $x_1_7 = "psephomancy" ascii //weight: 1
        $x_1_8 = "scyphostoma" ascii //weight: 1
        $x_1_9 = "PlzDFDPNkuWemnCIVCBnufYpcOfWCHpfA" ascii //weight: 1
        $x_1_10 = "LOHzIqOoIFlXUIKfiEKCkgLiDpyCphr" ascii //weight: 1
        $x_1_11 = "vector too long" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_CP_2147834389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.CP!MTB"
        threat_id = "2147834389"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 6c 24 38 8b 5c 24 34 83 c5 56 8b 7c 24 34 83 c3 36 8b 74 24 28 83 c7 5b 8b 54 24 38 83 ee 48 8b 4c 24 24 83 c2 34 8b 44 24 30}  //weight: 1, accuracy: High
        $x_1_2 = {8b 7c 24 48 83 eb 3a 8b 74 24 54 81 c7 ?? ?? ?? ?? 8b 54 24 60 83 c6 06 8b 4c 24 44 83 ea 34 89 84 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_EB_2147835065_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.EB!MTB"
        threat_id = "2147835065"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {33 d2 03 04 24 13 54 24 04 83 c4 08}  //weight: 3, accuracy: High
        $x_2_2 = {29 04 24 19 54 24 04 58 5a 2b d8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_EB_2147835065_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.EB!MTB"
        threat_id = "2147835065"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 45 a4 8b 45 d8 8b 55 a8 01 10 8b 45 c4 03 45 a4 89 45 a0 6a 00 e8 ?? ?? ?? ?? 03 45 a0 40 8b 55 d8 33 02 89 45 a0}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_EB_2147835065_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.EB!MTB"
        threat_id = "2147835065"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pibiconv_set_relocation_prefix" ascii //weight: 1
        $x_1_2 = "MS_KANJI" ascii //weight: 1
        $x_1_3 = "WINBALTRIM" ascii //weight: 1
        $x_1_4 = "#b#d#f#h#j#l#n#p#r#t#v#x#z#|#~#" ascii //weight: 1
        $x_1_5 = "pconv_canonicalize" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_EB_2147835065_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.EB!MTB"
        threat_id = "2147835065"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "QIaKHHdIaeyzVyMpKKdDjWJPMThNJjmVi" wide //weight: 1
        $x_1_2 = "ibdWVlZBCmHPLalDfGpPGmFWPvceeTCTY" wide //weight: 1
        $x_1_3 = "nfOTLlSfsJ" wide //weight: 1
        $x_1_4 = "zrzKvkUbHeynTTMtG" wide //weight: 1
        $x_1_5 = "KPboVkv" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RH_2147835211_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RH!MTB"
        threat_id = "2147835211"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2b d8 8b 45 d8 33 18 89 5d a0 8b 45 d8 8b 55 a0 89 10 8b 45 a8 83 c0 04 89 45 a8 33 c0 89 45 a4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RH_2147835211_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RH!MTB"
        threat_id = "2147835211"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 88 c4 00 00 00 29 88 98 00 00 00 8b 88 fc 00 00 00 0f af da 8d 51 ff 33 d1 89 90 fc 00 00 00 8b 88 00 01 00 00 01 48 50 8b 88 ec 00 00 00 01 48 10 8b 90 80 00 00 00 8b 88 a8 00 00 00 88 1c 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RI_2147835305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RI!MTB"
        threat_id = "2147835305"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 86 d8 00 00 00 03 c1 89 46 7c b8 7d a4 15 00 2b 46 10 01 46 2c 8b 86 94 00 00 00 35 7c 8c 0f 00 29 86 a4 00 00 00 8b c2 0f af c2 01 86 f4 00 00 00 8b 86 fc 00 00 00 05 84 8f 02 00 03 46 48 31 86 b0 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_NEAA_2147836972_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.NEAA!MTB"
        threat_id = "2147836972"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "28"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "vuKFSbljPKKNky" ascii //weight: 5
        $x_5_2 = "DKeSFYzdDzExGobaroPCTeZs" ascii //weight: 5
        $x_2_3 = "leptoprosopy" ascii //weight: 2
        $x_2_4 = "unrecallably" ascii //weight: 2
        $x_2_5 = "antichristian" ascii //weight: 2
        $x_2_6 = "teledendron" ascii //weight: 2
        $x_2_7 = "dejeration" ascii //weight: 2
        $x_2_8 = "singingly" ascii //weight: 2
        $x_2_9 = "Piriform Ltd" wide //weight: 2
        $x_2_10 = "2, 29, 0, 1111" wide //weight: 2
        $x_2_11 = "ccleaner.exe" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_NEAB_2147837431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.NEAB!MTB"
        threat_id = "2147837431"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "43"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "C:\\Users\\conemu\\SRC\\conemu\\src\\ConEmuTh\\ConEmuTh.cpp" ascii //weight: 5
        $x_3_2 = "ConEmuTh.dll" wide //weight: 3
        $x_3_3 = "ConEmu.Maximus5@gmail.com" wide //weight: 3
        $x_2_4 = "k4.HYRQ" ascii //weight: 2
        $x_2_5 = "msmpeng.exe" wide //weight: 2
        $x_2_6 = "FarPictureViewControlClass" wide //weight: 2
        $x_2_7 = "smss.exe" wide //weight: 2
        $x_2_8 = "wmplayer.exe" wide //weight: 2
        $x_2_9 = "tlntsess.exe" wide //weight: 2
        $x_2_10 = "yahoomessenger.exe" wide //weight: 2
        $x_2_11 = "notepad.exe" wide //weight: 2
        $x_2_12 = "mrt.exe" wide //weight: 2
        $x_2_13 = "norton.exe" wide //weight: 2
        $x_2_14 = "outpost.exe" wide //weight: 2
        $x_2_15 = "spoolsv.exe" wide //weight: 2
        $x_2_16 = "winlogon.exe" wide //weight: 2
        $x_2_17 = "msmpsvc.exe" wide //weight: 2
        $x_2_18 = "avp32.exe" wide //weight: 2
        $x_2_19 = "antivirus.exe" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_NEAC_2147837966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.NEAC!MTB"
        threat_id = "2147837966"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 55 f4 03 55 c8 8b 45 ec 03 45 c4 8b 4d d4 e8 ?? ?? ?? ?? 8b 45 d4 01 45 c4 8b 45 d4 01 45 c8 8b 45 d0 01 45 c8 eb c6}  //weight: 5, accuracy: Low
        $x_5_2 = {03 d8 8b 45 ec 31 18}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_PBC_2147840250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.PBC!MTB"
        threat_id = "2147840250"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UsImgDetBeginDetection" ascii //weight: 1
        $x_1_2 = "UsImgDetBeginDetectionBanding" ascii //weight: 1
        $x_1_3 = "UsImgDetBeginSession" ascii //weight: 1
        $x_1_4 = "UsImgDetEndDetection" ascii //weight: 1
        $x_1_5 = "UsImgDetEndDetectionBanding" ascii //weight: 1
        $x_1_6 = "UsImgDetEndSession" ascii //weight: 1
        $x_1_7 = "Wind" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_AD_2147840554_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.AD!MTB"
        threat_id = "2147840554"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b ca 01 48 ?? 8b 48 ?? 81 e9 ?? ?? ?? ?? 31 48 ?? 8b 50 ?? 2b 50 ?? 33 50 ?? 81 f2 ?? ?? ?? ?? 89 50 ?? 8b 48 ?? 33 88 ?? ?? ?? ?? 83 f1 ?? 29 88 ?? ?? ?? ?? 8b 48 ?? 03 48 ?? 31 88 ?? ?? ?? ?? 81 ff ?? ?? ?? ?? 0f 8c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_AE_2147841210_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.AE!MTB"
        threat_id = "2147841210"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 52 6b 64 65 5f 69 6e 74 65 72 6e 61 6c 5f 4b 43 6f 6e 66 69 67 47 72 6f 75 70 47 75 69 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 57 69 6e 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_AF_2147842682_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.AF!MTB"
        threat_id = "2147842682"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd\\1f\\out\\binaries\\x86ret\\bin\\i386\\Graphics\\dxtex.pdb" ascii //weight: 1
        $x_1_2 = {00 58 4c 35 35 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 52 6f 61 64 46 72 6f 6d 46 69 6c 65 49 6e 4d 65 6d 6f 72 79 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_AG_2147842683_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.AG!MTB"
        threat_id = "2147842683"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 58 4c 35 35 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 52 73 63 5f 61 74 74 61 63 68 5f 64 61 74 61 62 61 73 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 52 73 63 5f 70 72 65 70 61 72 65 5f 74 72 61 6e 73 61 63 74 69 6f 6e 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 52 64 73 5f 5f 74 72 61 6e 73 61 63 74 69 6f 6e 5f 63 6c 65 61 6e 75 70 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_AH_2147842877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.AH!MTB"
        threat_id = "2147842877"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 58 53 38 38 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 52 65 5f 6c 61 79 6f 75 74 43 68 61 72 73 5f 35 37 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 52 65 5f 67 65 74 47 6c 79 70 68 73 5f 35 37 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 52 65 5f 67 65 74 43 68 61 72 49 6e 64 69 63 65 73 5f 35 37 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 52 65 5f 63 72 65 61 74 65 5f 35 37 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_NEAD_2147843080_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.NEAD!MTB"
        threat_id = "2147843080"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "out\\binaries\\x86ret\\bin\\i386\\Graphics\\dxtex.pdb" ascii //weight: 5
        $x_2_2 = "/gAMA/ImageGamma" wide //weight: 2
        $x_1_3 = "RonvertPixelFormat" ascii //weight: 1
        $x_1_4 = "IsProcessorFeaturePresent" ascii //weight: 1
        $x_1_5 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_AK_2147843302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.AK!MTB"
        threat_id = "2147843302"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 47 4c 37 30 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 44 65 74 5f 63 68 69 6c 64 72 65 6e 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 44 6e 6f 6d 65 5f 61 63 63 65 73 73 69 62 69 6c 69 74 79 5f 6d 6f 64 75 6c 65 5f 73 68 75 74 64 6f 77 6e 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 44 61 69 6c 5f 74 65 78 74 5f 76 69 65 77 5f 67 65 74 5f 74 79 70 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 44 61 69 6c 5f 72 65 6e 64 65 72 65 72 5f 63 65 6c 6c 5f 6e 65 77 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 44 61 69 6c 5f 73 74 61 74 75 73 62 61 72 5f 67 65 74 5f 74 79 70 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_PBE_2147843790_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.PBE!MTB"
        threat_id = "2147843790"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 4c 05 ?? 3a c9 8b 45 ?? 33 d2 3a f6 bb 04 00 00 00 53 3a ff 5e f7 f6 3a c9 0f b6 44 15 ?? 33 c8 66 3b ed 8b 45 ?? 88 4c 05 ac 8b 45 f4 40}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_AO_2147845532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.AO!MTB"
        threat_id = "2147845532"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 58 35 35 35 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 55 79 70 65 73 51 75 65 72 79 49 6e 74 65 72 66 61 63 65 56 65 72 73 69 6f 6e 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 55 79 70 65 73 51 75 65 72 79 54 69 4d 61 63 45 78 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 55 7a 43 61 6e 6f 6e 46 69 6c 65 6e 61 6d 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 55 79 70 65 73 49 73 54 79 70 65 53 65 72 76 65 64 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 55 72 75 6e 63 53 74 46 72 6f 6d 53 7a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_AP_2147845538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.AP!MTB"
        threat_id = "2147845538"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 58 35 35 35 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 54 6d 65 6d 6d 6f 76 65 5f 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 54 63 73 74 6f 6d 62 73 5f 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 54 63 73 6e 63 70 79 5f 73 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 54 66 77 70 72 69 6e 74 66 5f 73 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 54 6d 70 6e 61 6d 5f 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_NXA_2147845877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.NXA!MTB"
        threat_id = "2147845877"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b f8 a1 a4 90 4a 00 8b 14 24 c1 e2 08 2b d7 d1 ea 03 d7 c1 ea 11 30 14 18 43 8b 0d 3c 94 4a 00 3b d9 72 9f}  //weight: 1, accuracy: High
        $x_1_2 = {83 ec 28 64 a1 30 00 00 00 66 3b db}  //weight: 1, accuracy: High
        $x_1_3 = "Motd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_GID_2147846168_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.GID!MTB"
        threat_id = "2147846168"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RZ14KITEMVIEWS_LOGv" ascii //weight: 1
        $x_1_2 = "Rnm___ZN16QCoreApplication4selfE" ascii //weight: 1
        $x_1_3 = "RZN5QHashI21QPersistentModelIndex5QListIP7QWidgetEE6removeERKS0_" ascii //weight: 1
        $x_1_4 = "RZN5QListIN6QEvent4TypeEEC1ERKS2_" ascii //weight: 1
        $x_1_5 = "P7QWidgetE6removeERKS0_" ascii //weight: 1
        $x_1_6 = "RZN5QListIP7QWidgetEC1ERKS2_" ascii //weight: 1
        $x_1_7 = "RZNK5QHashI7QStringN16KCategorizedView7Private5BlockEE6valuesEv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_AQ_2147846297_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.AQ!MTB"
        threat_id = "2147846297"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 52 61 70 72 5f 66 69 6c 65 5f 6d 6b 74 65 6d 70 40 31 36 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 52 61 70 72 5f 66 69 6c 65 5f 6e 61 6d 65 5f 67 65 74 40 38 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 52 61 70 72 5f 66 69 6c 65 5f 6f 70 65 6e 5f 66 6c 61 67 73 5f 73 74 64 69 6e 40 31 32 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 52 61 70 72 5f 66 69 6c 65 5f 69 6e 68 65 72 69 74 5f 73 65 74 40 34 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 52 61 70 72 5f 66 69 6c 65 5f 64 75 70 32 40 31 32 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 54 69 6d 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_ZXX_2147846315_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.ZXX!MTB"
        threat_id = "2147846315"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "X555" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RPY_2147848519_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RPY!MTB"
        threat_id = "2147848519"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b fe 46 3b f0 72 f2 85 ff 74 18 8b 4d fc 8b d7 2b d9 66 8b 04 0b 66 89 01 8d 49 02 83 ef 01 75 f1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_RPY_2147848519_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.RPY!MTB"
        threat_id = "2147848519"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 45 f0 0f b6 08 3a db 74 40 bb 08 00 00 00 53 3a db 74 4e 03 45 f0 88 08 e9 b8 01 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {5e f7 f6 66 3b c0 74 c2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_PBF_2147848956_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.PBF!MTB"
        threat_id = "2147848956"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c3 01 83 c3 00 53 5e 66 3b ff f7 f6 8b 45 fc 66 3b ed 0f b6 44 10 ?? 33 c8 66 3b c9 8b 45 ?? 03 45 ?? 88 08 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_PBG_2147849021_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.PBG!MTB"
        threat_id = "2147849021"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {fc 8b 4d 0c ac 02 c3 32 c3 8b f6 8b ff c0 c8 e6 8b db aa 8b e4 49 e9}  //weight: 10, accuracy: Low
        $x_1_2 = "must" ascii //weight: 1
        $x_10_3 = {8b 74 64 04 f3 a4 be ?? ?? ?? ?? 68 00 00 00 00 ff d3 4e 0f 85 ?? ?? ?? ?? c2 04 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_PBI_2147849251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.PBI!MTB"
        threat_id = "2147849251"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 45 f0 0f b6 08 eb ?? 0f b6 44 10 ?? 33 c8 eb 3b bb 03 00 00 00 83 c3 05 eb ?? 8b 45 f0 33 d2 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_DM_2147849371_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.DM!MTB"
        threat_id = "2147849371"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2b d8 6a 00 e8 [0-4] 03 d8 6a 00 e8 [0-4] 2b d8 6a 00 e8 [0-4] 03 d8 6a 00 e8 [0-4] 2b d8 8b 45 d4 31 18 83 45 ec 04 83 45 d4 04 8b 45 ec 3b 45 d0 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_GKH_2147849920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.GKH!MTB"
        threat_id = "2147849920"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "iairo_pdf_surface_create_for_stream" ascii //weight: 1
        $x_1_2 = "iairo_user_font_face_get_unicode_to_glyph_func" ascii //weight: 1
        $x_1_3 = "iairo_region_xor_rectangle" ascii //weight: 1
        $x_1_4 = "iairo_raster_source_pattern_get_snapshot" ascii //weight: 1
        $x_1_5 = "iairo_in_clip" ascii //weight: 1
        $x_1_6 = "hLaWyMssQsYniDY" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_PAH_2147902096_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.PAH!MTB"
        threat_id = "2147902096"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4d 1c 8b 95 0c 01 00 00 8b 45 04 8a 0c 39 32 0c 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_AI_2147903122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.AI!MTB"
        threat_id = "2147903122"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 05 60 1a 00 10 [0-4] 89 45 f0 0f b6 0d 60 1a 00 10 8b 55 f0 2b d1 89 55 f0 0f b6 05 60 1a 00 10 33 45 f0 89 45 f0}  //weight: 2, accuracy: Low
        $x_2_2 = {89 45 f0 0f b6 0d 60 1a 00 10 33 4d f0 89 4d f0 0f b6 15 60 1a 00 10 8b 45 f0 2b c2 89 45 f0 0f b6 0d 60 1a 00 10}  //weight: 2, accuracy: High
        $x_1_3 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qbot_AC_2147903123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.AC!MTB"
        threat_id = "2147903123"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d1 c7 45 e8 ?? ?? ?? ?? c7 45 ec ?? ?? ?? ?? 8a 44 15 ?? 34 ?? 88 44 15 ?? 42 83 fa 0c 7c ?? 88 4d ?? 8d 55 ?? eb}  //weight: 1, accuracy: Low
        $x_1_2 = {8b d1 c7 45 f8 ?? ?? ?? ?? c6 45 fc ?? 8a 44 15 ?? 2c 2d 88 44 15 ?? 42 83 fa 09 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qbot_BAA_2147941280_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbot.BAA!MTB"
        threat_id = "2147941280"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Couldn't open the file" ascii //weight: 1
        $x_1_2 = "@echo off" ascii //weight: 1
        $x_1_3 = "%windir%\\system32\\slmgr.vbs" ascii //weight: 1
        $x_1_4 = "net stop DPS" ascii //weight: 1
        $x_1_5 = "sc config DPS start= disabled" ascii //weight: 1
        $x_1_6 = "netsh advfirewall set allprofiles state offvisua" ascii //weight: 1
        $x_1_7 = "@%SystemRoot%\\system32\\shell32.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

