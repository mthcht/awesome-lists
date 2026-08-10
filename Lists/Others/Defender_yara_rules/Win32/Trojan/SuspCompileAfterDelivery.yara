rule Trojan_Win32_SuspCompileAfterDelivery_AM_2147975823_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspCompileAfterDelivery.AM"
        threat_id = "2147975823"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspCompileAfterDelivery"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "csc.exe" wide //weight: 1
        $n_1_2 = "019fe304-819c-7145-9a8b-7e4ad866a904" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SuspCompileAfterDelivery_JM_2147975824_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspCompileAfterDelivery.JM"
        threat_id = "2147975824"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspCompileAfterDelivery"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "csc.exe" wide //weight: 1
        $n_1_2 = "019fe304-d672-7347-ad5a-9f9c267bfa4f" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SuspCompileAfterDelivery_GR_2147975825_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspCompileAfterDelivery.GR"
        threat_id = "2147975825"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspCompileAfterDelivery"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wmic.exe" wide //weight: 1
        $n_1_2 = "019fe316-0ca3-7423-9e58-b596df330c0a" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SuspCompileAfterDelivery_MA_2147975826_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspCompileAfterDelivery.MA"
        threat_id = "2147975826"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspCompileAfterDelivery"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wmic.exe" wide //weight: 1
        $n_1_2 = "019fe315-9c36-7cfa-a034-db72339bbaa6" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

