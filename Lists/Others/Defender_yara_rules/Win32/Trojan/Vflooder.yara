rule Trojan_Win32_Vflooder_YA_2147735351_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vflooder.YA!MTB"
        threat_id = "2147735351"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vflooder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Content-Disposition: form-data; name=\"file\"; filename=\"1.exe\"" ascii //weight: 1
        $x_1_2 = "/vtapi/v2/file/scan" wide //weight: 1
        $x_1_3 = "/pidoras6" wide //weight: 1
        $x_1_4 = "twitter.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vflooder_2147752447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vflooder!MSR"
        threat_id = "2147752447"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vflooder"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VMGrab" ascii //weight: 1
        $x_1_2 = "a6281279.yolox.net" ascii //weight: 1
        $x_1_3 = "vtapi/v2/file/scan" ascii //weight: 1
        $x_1_4 = "Qkkbal" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vflooder_RPZ_2147851903_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vflooder.RPZ!MTB"
        threat_id = "2147851903"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vflooder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vtboss.yolox.net" wide //weight: 1
        $x_1_2 = "/md5.php" wide //weight: 1
        $x_1_3 = "Content-Transfer-Encoding: binary" ascii //weight: 1
        $x_1_4 = ".ropf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vflooder_EM_2147851997_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vflooder.EM!MTB"
        threat_id = "2147851997"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vflooder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "msn://@ui.mar@/chanbar.htm" wide //weight: 1
        $x_1_2 = "E8055863-4956-4cbf-9CA5-46FF053A904C" wide //weight: 1
        $x_1_3 = "market32.mar" wide //weight: 1
        $x_1_4 = "msnuserdata.txt" wide //weight: 1
        $x_1_5 = "drop\\bbinstr\\dump\\opt\\msn6.exe.pdb" ascii //weight: 1
        $x_1_6 = "msn6.pdb" ascii //weight: 1
        $x_1_7 = "-buddies" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vflooder_DS_2147852928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vflooder.DS!MTB"
        threat_id = "2147852928"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vflooder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ba ae 64 13 74 03 3b 29 91 75 41 fd 65 ae fb 13 72 41 3d 1f 01 25 00 30 00 31 c6 ba 2f d6 d3 64}  //weight: 1, accuracy: High
        $x_1_2 = {68 3f e8 1f c6 80 34 1c 53 0e 55 e4 52 f3 e5 f8 25 e0 6a 14 8d 0c 0a 5c 33 6e 2f 46 8d 2b 22 57 e0 50 0a 59 46}  //weight: 1, accuracy: High
        $x_1_3 = {8b 14 fe ba cf 1e 89 41 08 17 a3 60 32 1c 15 05 52 68 ec af 33 9b fb 5c 10 0a 1b 48 90 a1 18 fe 1e 48 f3 50 68 00 22 38 8b 0d 19 51 68 18 b0 7b f2 7c 10 30 4c 68 98 18 6a 01 6e f6 7b f3 0c 80 85 c0 74}  //weight: 1, accuracy: High
        $x_1_4 = {05 4d 08 02 1e 6c 36 35 b3 8c e8 e8 03 0f 00 01 4d d3 6d c3 44 99 10 29 0c e8 5c 37 d3 2c 23}  //weight: 1, accuracy: High
        $x_1_5 = "4a3191ba1afde52613" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

