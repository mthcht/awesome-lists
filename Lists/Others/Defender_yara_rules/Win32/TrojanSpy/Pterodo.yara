rule TrojanSpy_Win32_Pterodo_A_2147720205_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Pterodo.A"
        threat_id = "2147720205"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Pterodo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 53 42 67 72 61 62 62 65 72 2e 64 6c 6c 00 53 74 61 72 74 42 61 63 6b 75 70}  //weight: 1, accuracy: High
        $x_1_2 = "__Wsnusb73__" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Pterodo_A_2147720205_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Pterodo.A"
        threat_id = "2147720205"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Pterodo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "USBgrabber.dll" ascii //weight: 1
        $x_1_2 = "Content-Disposition: form-data; name=\"compname\"" ascii //weight: 1
        $x_1_3 = "Content-Disposition: form-data; name=\"w\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

