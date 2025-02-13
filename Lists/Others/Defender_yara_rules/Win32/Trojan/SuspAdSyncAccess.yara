rule Trojan_Win32_SuspAdSyncAccess_A_2147897355_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspAdSyncAccess.A!EntraConnect"
        threat_id = "2147897355"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspAdSyncAccess"
        severity = "Critical"
        info = "EntraConnect: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "powershell" wide //weight: 10
        $x_5_2 = "microsoft.directoryservices.metadirectoryservices.cryptography.keymanager" wide //weight: 5
        $x_5_3 = ".loadkeyset(" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

