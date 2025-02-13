rule Ransom_MSIL_Piegez_A_2147726722_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Piegez.A"
        threat_id = "2147726722"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Piegez"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "D:\\[!]Dn13\\Ransomware\\Project Final\\Backup H34rtBl33d\\anu\\1\\KNTLCrypt\\obj\\x86\\Debug\\DnThirTeen.pdb" ascii //weight: 4
        $x_2_2 = "D3g1d5.zip" ascii //weight: 2
        $x_2_3 = "d3g1d5.exe" ascii //weight: 2
        $x_2_4 = "H34rtBl33d.bmp" ascii //weight: 2
        $x_2_5 = "H34rtBl33d.html" ascii //weight: 2
        $x_2_6 = "H34rtBl33d.txt" ascii //weight: 2
        $x_2_7 = "H34rtBl33d.exe" ascii //weight: 2
        $x_2_8 = "H34rtBl33d Debug" ascii //weight: 2
        $x_2_9 = "H34rtBl33d Ransomware" ascii //weight: 2
        $x_2_10 = "Go Home Kidz, Zuahahaha!" ascii //weight: 2
        $x_2_11 = "Pay Some Money To Recover Your Data, Zuahahahaha!" ascii //weight: 2
        $x_2_12 = "[!]H34rtBl33d" ascii //weight: 2
        $x_2_13 = "[!]DnThirteen" ascii //weight: 2
        $x_2_14 = "D3G1D5Crypt" ascii //weight: 2
        $x_2_15 = "D3G1D5CYBERCREW" ascii //weight: 2
        $x_2_16 = "D3G1D5 Cyber Crew" ascii //weight: 2
        $x_2_17 = "Net user D3g1d5 Dwixtkj37 /add" ascii //weight: 2
        $x_2_18 = "Net localgroup Administrators D3g1d5 /add" ascii //weight: 2
        $x_1_19 = "vssadmin delete shadows /for=c: /all /quiet" ascii //weight: 1
        $x_1_20 = "vssadmin delete shadows /for=d: /all /quiet" ascii //weight: 1
        $x_1_21 = "bcdedit /set {bootmgr} displaybootmenu no" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((6 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 4 of ($x_2_*))) or
            (all of ($x*))
        )
}

