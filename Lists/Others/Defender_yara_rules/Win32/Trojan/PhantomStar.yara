rule Trojan_Win32_PhantomStar_A_2147724656_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PhantomStar.A!dha"
        threat_id = "2147724656"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PhantomStar"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "EDf3" wide //weight: 10
        $x_10_2 = "666666666666\\\\\\\\\\\\" ascii //weight: 10
        $x_10_3 = "OpenSSL 1.0.1q 3 Dec 2015" ascii //weight: 10
        $x_10_4 = "[system PrOcEss]" ascii //weight: 10
        $x_1_5 = "cm%sx%s\"%s %s %s\" 2>%" ascii //weight: 1
        $x_1_6 = "ping 0.0.0.0>nul" ascii //weight: 1
        $x_1_7 = "if exist %%1 goto P" ascii //weight: 1
        $x_1_8 = "/AUTOSTART" ascii //weight: 1
        $x_1_9 = "IEMutantClassObject" ascii //weight: 1
        $x_1_10 = "searchindEXeR.eXe" ascii //weight: 1
        $x_1_11 = "mpcmdrun.exe" ascii //weight: 1
        $x_1_12 = "CompatData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_PhantomStar_C_2147724657_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PhantomStar.C!dha"
        threat_id = "2147724657"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PhantomStar"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "[system prOceSs]" ascii //weight: 1
        $x_1_2 = "runDLl32.Exe" ascii //weight: 1
        $x_1_3 = "Mpcmdrun.eXe" ascii //weight: 1
        $x_1_4 = "wmpnETwk.exE" ascii //weight: 1
        $x_1_5 = "JavaFXPackagerMutant" ascii //weight: 1
        $x_1_6 = {2d eb 4a 00 00 50 ff 15 06 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

