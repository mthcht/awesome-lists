rule TrojanDownloader_Win32_Sindomorl_C_2147705750_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Sindomorl.C"
        threat_id = "2147705750"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Sindomorl"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "FB21D21FEA53E076CAB8954EF139D54ECF54B76892B372B0878F6DA67" wide //weight: 2
        $x_2_2 = "1439EA07123A0B5CEC67E41FC646C25DBE47C27DB95B959D929A62B36" wide //weight: 2
        $x_2_3 = "2ED30FDB29152633057FCC072EFD0A02031BFE21DD0721E149CD2FE03" wide //weight: 2
        $x_2_4 = "47EA18D4202C390EE71DEC0936FB0D1F3EDE24D07BA248DB64F00CF55" wide //weight: 2
        $x_2_5 = "80AD658194B885D222C549E91FE424F411EF6886BC6EC758E425E1321" wide //weight: 2
        $x_2_6 = "9947FC29FC411227EB1FF21FCA51CA49D821FC26CEB846D2192AFC1FF" wide //weight: 2
        $x_2_7 = "628F43EF05491A2FC16DA141F20C031E3D011FC37EAA4AC972BB4ECF4" wide //weight: 2
        $x_1_8 = "EGXevbfcFzGBlxqrjvMIDZgYbotpLaowpAEjnTgHLJohSyfTreVAyBFtM" wide //weight: 1
        $x_1_9 = "AB9980E8" wide //weight: 1
        $x_1_10 = "FB21D21FEA53E076CAB8954EF" wide //weight: 1
        $x_1_11 = "139D54ECF54B76892B372B087" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Sindomorl_D_2147705754_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Sindomorl.D"
        threat_id = "2147705754"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Sindomorl"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "30C254BF51DE5CE84A1622C76C9B41C87CA563A351E31FC2AA6592BE7" wide //weight: 4
        $x_4_2 = "B140D73BCA502D3F24300829CF678A9145FC1AF42EC67CA78F81B655E" wide //weight: 4
        $x_4_3 = "31C35BB848D755E74DE94E93B949EC34E719F617CC679C4428FA28C47" wide //weight: 4
        $x_4_4 = "B241D63CCD5DDE6DB541D56591A671B0995FA26F965781B34F093EFA7" wide //weight: 4
        $x_4_5 = "3BF90DF606151626C24CD66EA05E8487B169E738E11A0EC373A14EFB7" wide //weight: 4
        $x_4_6 = "BB7E917180EF4D1FD62CFA32DA192BFA18C55FBE66C162975FFA21C67" wide //weight: 4
        $x_4_7 = "1BD92DD6263536062FF030C677B071BFB4AD66A65C99B958E33FE1063" wide //weight: 4
        $x_4_8 = "AC4FA062B372FE4D2AF530CC708BA97BA39BB942E111C36B859E57F50" wide //weight: 4
        $x_4_9 = "35C75FA474B2BE8EEB37CF6C9155936189F554B858EF24CB1A0B3BE90" wide //weight: 4
        $x_2_10 = "ZcwaURcVhoRATQbDOpsFUGFZtEIPJfAAkofyfWIzqNdUCpYZPAvDnEcbz" wide //weight: 2
        $x_1_11 = "006BFA5C" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

