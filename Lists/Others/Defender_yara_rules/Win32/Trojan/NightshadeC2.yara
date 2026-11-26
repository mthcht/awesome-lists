rule Trojan_Win32_NightshadeC2_2147982852_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NightshadeC2!atmn"
        threat_id = "2147982852"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NightshadeC2"
        severity = "Critical"
        info = "atmn: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Get-ScheduledJob; Add-MpPreference -ExclusionPath '%ws'; echo 'e4u923rfhesd98vjde82efejw2r9fjws';" ascii //weight: 3
        $x_3_2 = "Add-MpPreference -ExclusionProcess '%ws'; echo '4o03tkfjd98sjv8dso3nuyrgbn';exit" ascii //weight: 3
        $x_2_3 = "SELECT value_encrypted FROM local_stored_cvc WHERE guid = '%ws'" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

