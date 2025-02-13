rule Trojan_PowerShell_Fifinopy_A_2147769743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/Fifinopy.A"
        threat_id = "2147769743"
        type = "Trojan"
        platform = "PowerShell: "
        family = "Fifinopy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell.exe" wide //weight: 1
        $x_1_2 = ":\\users\\" wide //weight: 1
        $x_1_3 = "[system.convert]::frombase64string" wide //weight: 1
        $x_1_4 = "[system.io.file]::readalltext(" wide //weight: 1
        $x_1_5 = "[system.io.file]::readallbytes(" wide //weight: 1
        $x_1_6 = "get-content" wide //weight: 1
        $x_1_7 = "remove-item" wide //weight: 1
        $x_1_8 = "iex" wide //weight: 1
        $x_1_9 = {66 00 6f 00 72 00 28 00 [0-48] 3d 00 30 00}  //weight: 1, accuracy: Low
        $x_1_10 = ".length" wide //weight: 1
        $x_1_11 = ".count" wide //weight: 1
        $x_1_12 = "-bxor " wide //weight: 1
        $x_1_13 = "[system.text.encoding]::utf8.getstring(" wide //weight: 1
        $x_1_14 = "[system.reflection.assembly]::load(" wide //weight: 1
        $x_1_15 = "::run()" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

