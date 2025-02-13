rule Trojan_MSIL_Chopper_AB_2147794348_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Chopper.AB!MTB"
        threat_id = "2147794348"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Chopper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Response.Write(new ActiveXObject(\"WScript.Shell\").Exec(\"cmd.exe /c nltest /domain_trusts /all_trusts\").StdOut.ReadAll());" ascii //weight: 1
        $x_1_2 = "Response.Write(new ActiveXObject(\"WScript.Shell\").Exec(\"cmd.exe /c systeminfo\").StdOut.ReadAll());" ascii //weight: 1
        $x_2_3 = "Response.Write(new ActiveXObject(\"WScript.Shell\").Exec(\"cmd.exe /c ipconfig /all\").StdOut.ReadAll());" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Chopper_AC_2147794443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Chopper.AC!MTB"
        threat_id = "2147794443"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Chopper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 16 06 1f 12 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a a2 25 17 06 1f 2c 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a a2 25 18 06 1f 16 28 ?? ?? ?? 0a 28 07 00 00 0a a2 25 19 06 17 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a a2 25 1a 06 1f 25 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a a2 25 1b 06 1f 0a 28}  //weight: 1, accuracy: Low
        $x_1_2 = "LaTkWfI64XeDAXZS6pU1KrsvLAcGH7AZOQXjrFkT816RnFYJQR" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Chopper_AD_2147794444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Chopper.AD!MTB"
        threat_id = "2147794444"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Chopper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Response.Write(new ActiveXObject(\"WScript.Shell\").Exec(\"cmd.exe /c systeminfo\").StdOut.ReadAll());" ascii //weight: 1
        $x_1_2 = "JScriptEvaluate" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Chopper_AE_2147795878_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Chopper.AE!MTB"
        threat_id = "2147795878"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Chopper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Response.Write(new ActiveXObject(\"WScript.Shell\").Exec(\"cmd.exe /c" ascii //weight: 1
        $x_1_2 = "JScriptEvaluate" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Chopper_EWM_2147824723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Chopper.EWM!MTB"
        threat_id = "2147824723"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Chopper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%76%61%72%20%78%3d%52%65%71%75" wide //weight: 1
        $x_1_2 = "%65%73%74%5b%22%63%61%64%61%74%61%4b%65%79%22%5d%3b%69%66%28%78%29%7b%65%76" wide //weight: 1
        $x_1_3 = "%61%6c%28%78%29%3b%7d%65%6c%73%65%7b%52%65%73%70%6f%6e%73%65%2e%53%74%61%74%75%73%43%6f%64%65%3d%34%30%34%3b%7d" wide //weight: 1
        $x_1_4 = "%76%61%72%20%79%3d%52%65%71" wide //weight: 1
        $x_1_5 = "%75%65%73%74%5b%22%63%61%64%61%74%61%4b%65%79%22%5d%3b%69%66%28%79%29%7b%65%76%61" wide //weight: 1
        $x_1_6 = "%6c%28%79%29%3b%7d%65%6c%73%65%7b%52%65%73%70%6f%6e%73%65%2e%52%65%64%69%72%65%63%74%28%22%2f%6f%77%61%2f%61%75%74" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_MSIL_Chopper_ACR_2147845732_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Chopper.ACR!MTB"
        threat_id = "2147845732"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Chopper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {25 16 03 a2 25 17 04 a2 25 18 06 a2 26 08 07 02 6f 12 00 00 0a 28 18 00 00 0a 74 1a 00 00 01 7b 19 00 00 0a 25 16 03 a2 25 17 04 a2 25}  //weight: 2, accuracy: High
        $x_2_2 = {25 16 9a 74 12 00 00 01 fe 0b 01 00 25 17 9a 74 13 00 00 01 fe 0b 02 00 25 18 9a 0a 26 02 6f 12 00 00 0a 28 18 00 00 0a 74 1a 00 00 01 7b 19 00 00 0a 25 16 03 a2 25 17 04 a2 25 18 06 a2 26 02}  //weight: 2, accuracy: High
        $x_1_3 = "__Render__control1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Chopper_MAAA_2147847528_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Chopper.MAAA!MTB"
        threat_id = "2147847528"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Chopper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 12 00 00 01 fe 0b 01 00 25 17 9a 74 13 00 00 01 fe 0b 02 00 25 18 9a 0a 26 02 6f 12 00 00 0a 28 18 00 00 0a 74 1a 00 00 01 7b 19 00 00 0a 25 16 03 a2 25 17 04 a2 25 18 06 a2 26 02 6f 12 00 00 0a 28 18 00 00 0a}  //weight: 1, accuracy: High
        $x_1_2 = {57 17 a2 03 09 00 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 27 00 00 00 05 00 00 00 04 00 00 00 17 00 00 00 04 00 00 00 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Chopper_SPD_2147890122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Chopper.SPD!MTB"
        threat_id = "2147890122"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Chopper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0a 02 6f 12 00 00 0a 28 ?? ?? ?? 0a 74 ?? ?? ?? 01 7b ?? ?? ?? 0a 25 16 03 a2 25 17 04 a2 25 18 06 a2 26 02}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Chopper_PTGX_2147901331_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Chopper.PTGX!MTB"
        threat_id = "2147901331"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Chopper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {d0 03 00 00 02 72 b7 03 00 70 72 e1 03 00 70 16 8d 0f 00 00 01 1a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

