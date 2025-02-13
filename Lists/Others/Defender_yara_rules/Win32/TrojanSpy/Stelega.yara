rule TrojanSpy_Win32_Stelega_MR_2147767760_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Stelega.MR!MTB"
        threat_id = "2147767760"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Stelega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_7_1 = {b1 ea f6 d8 b2 5e c0 c8 03 2a c8 b0 02 80 f1 60 2a d1 b1 13 32 d3 80 ea 5b 32 d3 2a c2 2a c3 32 c3 2a c8 32 cb 2a cb fe c9 80 f1 5f 80 c1 19 32 cb d0 c1 f6 d9 80 f1 7b f6 d1 2a cb 32 cb 80 e9 4f c0 c1 03 80 c1 12 88 8b ?? ?? ?? ?? 43 81 fb ?? ?? ?? ?? 72 06 00 8a 83}  //weight: 7, accuracy: Low
        $x_1_2 = "contact.dll" ascii //weight: 1
        $x_1_3 = "Welcome to a0 contact Manager" ascii //weight: 1
        $x_1_4 = "urlmon.dll" ascii //weight: 1
        $x_1_5 = "Edita Contact" ascii //weight: 1
        $x_1_6 = "E-mail ad" ascii //weight: 1
        $x_1_7 = "WININET.dll" ascii //weight: 1
        $x_1_8 = "RESUTILS.dll" ascii //weight: 1
        $x_1_9 = "loadperf.dll" ascii //weight: 1
        $x_1_10 = "No match found!" ascii //weight: 1
        $x_1_11 = "Editing '%s'" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_7_*))) or
            (all of ($x*))
        )
}

