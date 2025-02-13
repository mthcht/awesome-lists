rule Worm_Win32_Ainslot_A_2147641238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Ainslot.A"
        threat_id = "2147641238"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Ainslot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "modSpread" ascii //weight: 1
        $x_1_2 = "modSocketMaster" ascii //weight: 1
        $x_1_3 = "modICallBack" ascii //weight: 1
        $x_1_4 = "modPWs" ascii //weight: 1
        $x_1_5 = "modInfect" ascii //weight: 1
        $x_1_6 = "modSniff" ascii //weight: 1
        $x_1_7 = "clsMSNpw" ascii //weight: 1
        $x_1_8 = "clsMSNpws" ascii //weight: 1
        $x_1_9 = "tmrScreenshot" ascii //weight: 1
        $x_1_10 = "StandardProfile /v \"DoNotAllowExceptions\"" wide //weight: 1
        $x_1_11 = "IMWindowClass" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Worm_Win32_Ainslot_C_2147644006_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Ainslot.C"
        threat_id = "2147644006"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Ainslot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mAntiDebug" ascii //weight: 1
        $x_1_2 = "mDecryption" ascii //weight: 1
        $x_1_3 = "mSandboxie" ascii //weight: 1
        $x_1_4 = "mKill" ascii //weight: 1
        $x_1_5 = "mDownloader" ascii //weight: 1
        $x_1_6 = "mCDBurn" ascii //weight: 1
        $x_1_7 = "mMsn" ascii //weight: 1
        $x_1_8 = "mUsb" ascii //weight: 1
        $x_2_9 = "|Shortcut Files|*.lnk|Picture Files|*.jpg;*.bmp;*.gif|DLL Files|*.dll" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Ainslot_H_2147646459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Ainslot.H"
        threat_id = "2147646459"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Ainslot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 fc 0b 00 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 89 45 80 c7 85 ?? ?? ?? ?? 08 00 00 00 6a 00}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 45 fc 15 00 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b d0 8d 4d a8 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = "\\zahir vb\\New Folder (2)" wide //weight: 1
        $x_1_4 = "scripting.filesystemobject" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Ainslot_K_2147654817_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Ainslot.K"
        threat_id = "2147654817"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Ainslot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "shell\\open\\command=.\\RECYCLER\\S-1-5-21-3441485041-918478196-174860263-1004\\" ascii //weight: 1
        $x_1_2 = "%c:\\autorun.inf" ascii //weight: 1
        $x_1_3 = "lgxfsrvc" ascii //weight: 1
        $x_1_4 = "115.145.229.85" ascii //weight: 1
        $x_1_5 = "--8cba7c0b4681f6e" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Worm_Win32_Ainslot_N_2147660551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Ainslot.N"
        threat_id = "2147660551"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Ainslot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UDPFlood" ascii //weight: 1
        $x_1_2 = "USB spreader running" wide //weight: 1
        $x_1_3 = "Select * from AntiVirusProduct" wide //weight: 1
        $x_1_4 = "Variant of PoisonIvy" wide //weight: 1
        $x_1_5 = "Variant of SpyNet RAT" wide //weight: 1
        $x_1_6 = "Variant of Zeus BOT" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Ainslot_O_2147662167_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Ainslot.O"
        threat_id = "2147662167"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Ainslot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_YahOo_\\My LiNk\\BlackShades\\de Dark Eye\\EMINeM" ascii //weight: 1
        $x_1_2 = "@~~@Inetnt Cleaneaar@~~@" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Ainslot_AI_2147663188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Ainslot.AI"
        threat_id = "2147663188"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Ainslot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 00 32 00 39 00 6d 00 64 00 48 00 64 00 68 00 63 00 6d 00 56 00 63 00 58 00 45 00 31 00 70 00 59 00 33 00 4a 00 76 00 63 00 32 00 39 00 6d 00 64 00 46 00 78 00 63 00 56 00 32 00 6c 00 75 00 5a 00 47 00 39 00 33 00 63 00 31 00 78 00 63 00 51 00 33 00 56 00 79 00 63 00 6d 00 56 00 75 00 64 00 46 00 5a 00 6c 00 63 00 6e 00 4e 00 70 00 62 00 32 00 35 00 63 00 58 00 46 00 4a 00 31 00 62 00 67 00 3d 00 3d 00 00 1f 58 00 58 00 58 00 30 00 30 00 30 00 59 00 59 00 59 00 39 00 39 00 39 00 5a 00 5a 00 5a 00 00 03 5c 00 00 39 53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 44 00 69 00 72 00 65 00 63 00 74 00 6f 00 72 00 79 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 2e 00 65 00 78 00 65 00 00 31 53 00 79 00 73 00 74 00 65 00 6d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Ainslot_GNE_2147924852_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Ainslot.GNE!MTB"
        threat_id = "2147924852"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Ainslot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {3c 67 32 00 4c c0 4b ?? ?? 4f 40 00 10 4f 40 00 40 ?? 0a 00}  //weight: 5, accuracy: Low
        $x_5_2 = {40 00 10 3e 32 00 30 4f ?? 00 03 00 03 00 d3 1d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

