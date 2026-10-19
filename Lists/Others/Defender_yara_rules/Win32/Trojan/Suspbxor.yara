rule Trojan_Win32_Suspbxor_ZZ_2147979206_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Suspbxor.ZZ!MTB"
        threat_id = "2147979206"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Suspbxor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "-bxor" wide //weight: 10
        $x_10_2 = "user32.dll" wide //weight: 10
        $x_1_3 = ";[rEfLeCTioN.AsSeMbLy]::lOaD($" wide //weight: 1
        $x_1_4 = "+[ChaR]" wide //weight: 1
        $x_1_5 = "iex([TExT.ENCodiNg]::UTF8.GetString($" wide //weight: 1
        $x_1_6 = "[Io.fILE]::ReadAllBytes($" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Suspbxor_BA_2147980373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Suspbxor.BA!MTB"
        threat_id = "2147980373"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Suspbxor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "[chAR]($_ -bXor" wide //weight: 10
        $x_10_2 = "[char]([byte]$_-bxor$" wide //weight: 10
        $x_10_3 = "[ChAr](`$_ -Bxor" wide //weight: 10
        $x_1_4 = "JOIn" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Suspbxor_BB_2147980374_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Suspbxor.BB!MTB"
        threat_id = "2147980374"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Suspbxor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-bxor [byte][char]$" wide //weight: 1
        $x_1_2 = "FromBase64String" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Suspbxor_BC_2147980375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Suspbxor.BC!MTB"
        threat_id = "2147980375"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Suspbxor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "::FromBase64String" wide //weight: 1
        $x_1_2 = ".GetBytes($" wide //weight: 1
        $x_1_3 = "[byte[]]::new($" wide //weight: 1
        $x_1_4 = "-bxor ($" wide //weight: 1
        $x_1_5 = "[System.IO.File]::WriteAllText" wide //weight: 1
        $x_1_6 = "[Guid]::NewGuid().ToString(" wide //weight: 1
        $x_1_7 = "[System.IO.File]::OpenRead" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Suspbxor_BD_2147980376_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Suspbxor.BD!MTB"
        threat_id = "2147980376"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Suspbxor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".Replace(" wide //weight: 1
        $x_1_2 = " System.IO.MemoryStream;$" wide //weight: 1
        $x_1_3 = "-bxor " wide //weight: 1
        $x_1_4 = "[System.Reflection.Assembly]::$" wide //weight: 1
        $x_1_5 = "System.Convert]::$" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Suspbxor_BE_2147980377_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Suspbxor.BE!MTB"
        threat_id = "2147980377"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Suspbxor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "([SCRIPtblock]::CrEATe($" wide //weight: 1
        $x_1_2 = "::fRoMBAse64STRiNg($" wide //weight: 1
        $x_1_3 = ".' + '" wide //weight: 1
        $x_1_4 = "-bxor" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Suspbxor_BE_2147980377_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Suspbxor.BE!MTB"
        threat_id = "2147980377"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Suspbxor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "System.Reflection.Assembly]::Load" wide //weight: 1
        $x_1_2 = "-bxor $" wide //weight: 1
        $x_1_3 = "[System.Convert]::FromBase64String" wide //weight: 1
        $x_1_4 = "[System.IO.File]::ReadAllText" wide //weight: 1
        $x_1_5 = "System.IO.MemoryStream" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Suspbxor_BF_2147980378_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Suspbxor.BF!MTB"
        threat_id = "2147980378"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Suspbxor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SCRIPtblock]::CrEATe" wide //weight: 10
        $x_10_2 = "-bxor" wide //weight: 10
        $x_1_3 = "[convert]::frombase64string" wide //weight: 1
        $x_1_4 = "Net.WebClient).DownloadData" wide //weight: 1
        $x_1_5 = "[Text.Encoding]::ASCII.GetString((@(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Suspbxor_BG_2147980379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Suspbxor.BG!MTB"
        threat_id = "2147980379"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Suspbxor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "icm ([scriptblock]::Create([Text.Encoding]::ASCII.GetString" wide //weight: 1
        $x_1_2 = "hidden" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Suspbxor_BH_2147980393_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Suspbxor.BH!MTB"
        threat_id = "2147980393"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Suspbxor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "]-bxor((0x" wide //weight: 1
        $x_1_2 = "[scriptblock]::create" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Suspbxor_BL_2147980394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Suspbxor.BL!MTB"
        threat_id = "2147980394"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Suspbxor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-bxor $" wide //weight: 1
        $x_1_2 = "[IO.File]::ReadAllBytes($" wide //weight: 1
        $x_1_3 = "[BitConverter]::ToInt32($" wide //weight: 1
        $x_1_4 = "byte[] $" wide //weight: 1
        $x_1_5 = "[IO.File]::WriteAllBytes" wide //weight: 1
        $x_1_6 = ".GetBytes($" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Suspbxor_BM_2147980395_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Suspbxor.BM!MTB"
        threat_id = "2147980395"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Suspbxor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "]-bXoR${" wide //weight: 1
        $x_1_2 = "[sYsteM.bYte[]]@(0x" wide //weight: 1
        $x_1_3 = "]::asCii.getstRing($" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Suspbxor_BN_2147980396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Suspbxor.BN!MTB"
        threat_id = "2147980396"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Suspbxor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-bxor $" wide //weight: 1
        $x_1_2 = "scriptblock]::Create(" wide //weight: 1
        $x_1_3 = "GetString($" wide //weight: 1
        $x_1_4 = "DownloadData" wide //weight: 1
        $x_1_5 = "WebClient" wide //weight: 1
        $x_1_6 = "[byte]0x" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Suspbxor_CA_2147980546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Suspbxor.CA!MTB"
        threat_id = "2147980546"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Suspbxor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-bxor $" wide //weight: 1
        $x_1_2 = "[Convert]::ToByte(([Convert]::ToString($" wide //weight: 1
        $x_1_3 = "Reflection.Assembly]::Load(" wide //weight: 1
        $x_1_4 = ".Invoke($" wide //weight: 1
        $x_1_5 = "[Convert]::ToByte($_" wide //weight: 1
        $x_1_6 = ".GetMethod" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Suspbxor_CB_2147980547_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Suspbxor.CB!MTB"
        threat_id = "2147980547"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Suspbxor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[Convert]::FromBase64String" wide //weight: 1
        $x_1_2 = "-bxor [byte][char]$" wide //weight: 1
        $x_1_3 = "Iex $" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Suspbxor_CC_2147980548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Suspbxor.CC!MTB"
        threat_id = "2147980548"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Suspbxor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[char]($_-bxor" wide //weight: 1
        $x_1_2 = ";iwr -Uri $" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Suspbxor_CD_2147980549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Suspbxor.CD!MTB"
        threat_id = "2147980549"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Suspbxor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[sYSteM.Io.FilE]::REaDALlbYTES(" wide //weight: 1
        $x_1_2 = "[sySTEM.refLecTiON.aSsemblY]::loAD($" wide //weight: 1
        $x_1_3 = "FOR($" wide //weight: 1
        $x_1_4 = "-gE $" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Suspbxor_CF_2147980550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Suspbxor.CF!MTB"
        threat_id = "2147980550"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Suspbxor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "([scriptblock]::Create" wide //weight: 1
        $x_1_2 = "Reflection.AssemblyName]" wide //weight: 1
        $x_1_3 = "-bor[Reflection" wide //weight: 1
        $x_1_4 = "-bxor $" wide //weight: 1
        $x_1_5 = "byte[]($" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Suspbxor_CG_2147980551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Suspbxor.CG!MTB"
        threat_id = "2147980551"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Suspbxor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".EntryPoint.Invoke($" wide //weight: 1
        $x_1_2 = "+''+[Char" wide //weight: 1
        $x_1_3 = "Reflection.Assembly]::Load" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

