rule TrojanDropper_Win32_PowerPunch_A_2147794018_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/PowerPunch.A!dha"
        threat_id = "2147794018"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "PowerPunch"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "210"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "powershell.exe" wide //weight: 100
        $x_100_2 = "Invoke-Expression -Command ([Text.Encoding]::Utf8.GetString([Convert]::" wide //weight: 100
        $x_10_3 = "FromBase64String('JG9tbmxvbyA9ICd1c2luZyBTeXN0ZW" wide //weight: 10
        $x_10_4 = "FromBase64String('JGdscGFrID0gJ3VzaW5nIFN5c3RlbT" wide //weight: 10
        $x_10_5 = "FromBase64String('JGJhZ3UgPSAndXNpbmcgU3lzdGVtOw" wide //weight: 10
        $x_10_6 = "FromBase64String('JGpla2JyID0gJ3VzaW5nIFN5c3RlbT" wide //weight: 10
        $x_10_7 = "FromBase64String('JGpxcXJkeSA9ICd1c2luZyBTeXN0ZW" wide //weight: 10
        $x_10_8 = "FromBase64String('JGpzcnUgPSAndXNpbmcgU3lzdGVtOw" wide //weight: 10
        $x_10_9 = "FromBase64String('JGR6cm8gPSAndXNpbmcgU3lzdGVtOw" wide //weight: 10
        $x_10_10 = "FromBase64String('JGRiYWcgPSAndXNpbmcgU3lzdGVtOw" wide //weight: 10
        $x_10_11 = "FromBase64String('JGVteHpwaiA9ICd1c2luZyBTeXN0ZW" wide //weight: 10
        $x_10_12 = "FromBase64String('JHpwZG5wciA9ICd1c2luZyBTeXN0ZW" wide //weight: 10
        $x_10_13 = "FromBase64String('JHZraG5iID0gJ3VzaW5nIFN5c3RlbT" wide //weight: 10
        $x_10_14 = "FromBase64String('JGNwaXpibiA9ICd1c2luZyBTeXN0ZW" wide //weight: 10
        $x_10_15 = "FromBase64String('JHBtZ3lxaCA9ICd1c2luZyBTeXN0ZW" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 11 of ($x_10_*))) or
            ((2 of ($x_100_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

