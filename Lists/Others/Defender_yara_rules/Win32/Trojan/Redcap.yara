rule Trojan_Win32_Redcap_A_2147754485_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redcap.A!MTB"
        threat_id = "2147754485"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redcap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b ca 2b cf f7 df 8b 09 89 4e 08 8b 54 3a fc 8b fa 2b f9 89 7e 0c 76 1b 33 ff 33 f6 46 83 ff 15 7f 0b 8a 1c 38 03 fe 30 19 03 ce eb 02 33 ff 3b ca 72 ea 33 c0 5e 5f 5b c2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redcap_AP_2147833537_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redcap.AP!MTB"
        threat_id = "2147833537"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redcap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {35 35 35 00 30 30 30 00 33 33 33 11 33 33 33 11 2f}  //weight: 3, accuracy: High
        $x_3_2 = {33 33 33 cd 33 33 33 f0 33 33 33 34 33 33 33 00 32 32 32 00 34 34}  //weight: 3, accuracy: High
        $x_1_3 = "someOtherProgram=SomeOtherProgram.exe" wide //weight: 1
        $x_1_4 = "searchbin.org" wide //weight: 1
        $x_1_5 = "data.bin" wide //weight: 1
        $x_1_6 = "Sendkeys" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redcap_BA_2147844824_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redcap.BA!MSR"
        threat_id = "2147844824"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redcap"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Hpsghserhseiohijs" ascii //weight: 2
        $x_2_2 = "Oosgoiwsejhoiejh" ascii //weight: 2
        $x_2_3 = "Weoigjosijhsejih" ascii //weight: 2
        $x_2_4 = "KDXKhhlMRPtUwYYFxrAVvOFO" ascii //weight: 2
        $x_2_5 = "oKcIZwBqZGLpSEntcFJeUULVidJxN" ascii //weight: 2
        $x_2_6 = "KxWXivwfCmuNdvpMimSEgsqebUuz" ascii //weight: 2
        $x_2_7 = "NGVSXHRuZmMbyrvWww" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redcap_BB_2147845619_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redcap.BB!MSR"
        threat_id = "2147845619"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redcap"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Noadfgioaejfigoaef" ascii //weight: 1
        $x_1_2 = "Noeajiofgseajigfesifg" ascii //weight: 1
        $x_1_3 = "AreFileApisANSI" ascii //weight: 1
        $x_1_4 = "GetNumaHighestNodeNumber" ascii //weight: 1
        $x_1_5 = "GetSystemFirmwareTable" ascii //weight: 1
        $x_1_6 = "InitializeSRWLock" ascii //weight: 1
        $x_1_7 = "TryEnterCriticalSection" ascii //weight: 1
        $x_1_8 = "GetLogicalDrives" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redcap_RJ_2147849646_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redcap.RJ!MTB"
        threat_id = "2147849646"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redcap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c2windows.exe" ascii //weight: 1
        $x_1_2 = "The injection has succeed" ascii //weight: 1
        $x_1_3 = "OneDrive\\CodeSource\\getexe_and_run\\Project1_1" ascii //weight: 1
        $x_1_4 = {51 6a 00 6a 00 6a 04 6a 01 6a 00 6a 00 6a 00 8d 8d 70 ff ff ff 51 ff d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redcap_AMAA_2147890318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redcap.AMAA!MTB"
        threat_id = "2147890318"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redcap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "H:\\PMS\\_AUpdate\\HanCapture\\bin\\Release\\Agent.pdb" ascii //weight: 1
        $x_1_2 = "Bogus JPEG colorspace" ascii //weight: 1
        $x_1_3 = "Bogus Huffman table definition" ascii //weight: 1
        $x_1_4 = "Sorry, there are legal restrictions" ascii //weight: 1
        $x_1_5 = "Wrong JPEG library" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redcap_NDA_2147921843_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redcap.NDA!MTB"
        threat_id = "2147921843"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redcap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "$PRIMARYBROWSER = \"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe\"" ascii //weight: 2
        $x_2_2 = "--kiosk --edge-kiosk-type=fullscreen --no-first-run" ascii //weight: 2
        $x_2_3 = "disable-popup-blocking --disable-extensions --no-default-browser-check --app=" ascii //weight: 2
        $x_1_4 = "$PRIMARYCLASS = \"[CLASS:Chrome_WidgetWin_1]\"" ascii //weight: 1
        $x_1_5 = "RUN ( $PRIMARYBROWSER &" ascii //weight: 1
        $x_1_6 = "$HWND = WINGETHANDLE ( $PRIMARYCLASS )" ascii //weight: 1
        $x_1_7 = "IF NOT WINACTIVE ( $HWND )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redcap_GNZ_2147925894_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redcap.GNZ!MTB"
        threat_id = "2147925894"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redcap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {32 0a 16 84 c6 5f 1d ?? ?? ?? ?? 31 1b e0}  //weight: 5, accuracy: Low
        $x_5_2 = {b1 6c 82 32 ae b4 39 e5 04 3b 20 38 c2}  //weight: 5, accuracy: High
        $x_1_3 = "MyUnregisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redcap_MBWG_2147928370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redcap.MBWG!MTB"
        threat_id = "2147928370"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redcap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 83 c4 f0 b8 4c d1 43 00 e8 30 9a fc ff 33 c0 55 68 75 07 44 00 64 ff 30 64 89 20 e8 ad bc ff ff 33 c0 5a 59 59 64 89 10 68 7c 07 44 00 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redcap_MKV_2147928644_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redcap.MKV!MTB"
        threat_id = "2147928644"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redcap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {81 ea d4 7f 00 00 81 ea 37 bd 00 00 e8 0a 00 00 00 00 4c 40 ?? 4f 34 3a 32 46 35 83 c4 04 81 e2 5d 1d 01 00 5a 56 56}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

