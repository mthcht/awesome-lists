rule Trojan_Win32_RasDialer_2147499978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RasDialer"
        threat_id = "2147499978"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RasDialer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "\\svchest.ini" ascii //weight: 5
        $x_5_2 = "C:\\1.tmp" ascii //weight: 5
        $x_1_3 = "HOST=0161,1100,mpe8/765" ascii //weight: 1
        $x_1_4 = "HOST=dxju,1100,mpe80./." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_RasDialer_N_2147608548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RasDialer.N"
        threat_id = "2147608548"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RasDialer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "302"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "SoftWare\\Visio RAS Script" ascii //weight: 100
        $x_100_2 = "%s\\%s.lnk" ascii //weight: 100
        $x_100_3 = "RasDialA" ascii //weight: 100
        $x_1_4 = "/min" ascii //weight: 1
        $x_1_5 = "adult" ascii //weight: 1
        $x_1_6 = "porn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_100_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_RasDialer_O_2147608794_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RasDialer.O"
        threat_id = "2147608794"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RasDialer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "GloDial" ascii //weight: 10
        $x_1_2 = "%c%c%cCURRENT: Pays: %s, ID: %s %c%c%cURL: %s%c%c%c" ascii //weight: 1
        $x_1_3 = "%c%c%cCustomer Support/Support Client: %c%c%c" ascii //weight: 1
        $x_1_4 = "YOU ARE CONNECTED FOR %s MINUTES" ascii //weight: 1
        $x_1_5 = "&gcskit=%s&gcslang=%s&gcscountry=%s" ascii //weight: 1
        $x_1_6 = "The price for this call will be" ascii //weight: 1
        $x_1_7 = "%c%c%cCUSTOMER SERVICE (FOR UK ONLY): 0870 800 8760" ascii //weight: 1
        $x_1_8 = "udpinfo.creanet.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_RasDialer_N_2147609960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RasDialer.N!dr"
        threat_id = "2147609960"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RasDialer"
        severity = "Critical"
        info = "dr: dropper component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "51"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 65 70 6c ?? 2e 65 78 65}  //weight: 10, accuracy: Low
        $x_10_2 = "mkc2489.exe" ascii //weight: 10
        $x_10_3 = "Software\\Visio RAS Script" ascii //weight: 10
        $x_10_4 = "KwZ_3" wide //weight: 10
        $x_5_5 = "epl%d.exe" ascii //weight: 5
        $x_5_6 = "Pb of connection - Try Again ?" ascii //weight: 5
        $x_1_7 = "ScriptVisio" ascii //weight: 1
        $x_1_8 = "if ex%s \"%s\" go%s y%s \"%%0\"" ascii //weight: 1
        $x_1_9 = "SpeakerMode_Dial" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_RasDialer_P_2147609962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RasDialer.P"
        threat_id = "2147609962"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RasDialer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {3a 52 65 70 65 61 74 0d 0a 64 65 6c 20 22 25 73 22 0d 0a 69 66 09 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 52 65 70 65 61 74 0d 0a 72 6d 64 69 72 20 22 25 73 22 0d 0a 64 65 6c 20 22 25 73 22}  //weight: 10, accuracy: High
        $x_10_2 = {74 77 61 69 6e 2d [0-3] 2e 69 6e 69}  //weight: 10, accuracy: Low
        $x_10_3 = {6f 70 65 6e 00 00 00 00 20 2d 2d 73 74 61 72 74 00 00 00 00 47 72 74 61 73 6b 00 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 00 00 00 2d 2d 74 72 61 79 00 00 52 61 73 47 65 74 43 6f 6e 6e 65 63 74 53 74 61 74 75 73 41}  //weight: 10, accuracy: High
        $x_1_4 = "AntyDial.exe" ascii //weight: 1
        $x_1_5 = "mks_mail.exe" ascii //weight: 1
        $x_1_6 = "SOFTWARE\\Microsoft\\RAS AutoDial\\Default" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

