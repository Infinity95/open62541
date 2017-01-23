param([string]$arch="32",
      [switch]$clean=$false,
      [string]$generator="Visual Studio 14 2015",
      [switch]$linux=$false,
      [switch]$help=$false
)

function build32 () {
    if ($clean)
    {
        Remove-Item -Recurse -Force "build" -ErrorAction SilentlyContinue
        Remove-Item -Recurse -Force "build" -ErrorAction SilentlyContinue
    }

    if (-Not (Test-Path "build"))
    {
        New-Item "build" -ItemType "directory"
    }

    if (Test-Path "build")
    {
        if (-Not $linux)
        {
            cmake . -Bbuild -G "$generator"
        }
        else 
        {
            # TODO: Need to force 32 bit compile in linux
            cmake . -Bbuild
        }
    }
}

function build64 () {
    if ($clean)
    {
        Remove-Item -Recurse -Force "build64"
    }

    if (-Not (Test-Path "build64"))
    {
        New-Item "build64" -ItemType "directory"
    }

    if (Test-Path "build64")
    {
        if (-Not $linux)
        {
            cmake . -Bbuild64 -G "$generator Win64"
        }
        else {
            # TODO: Need to force 64 bit compile in linux
            cmake . -Bbuild
        }
    }
}

if ($help)
{
    Write-Output '-arch -- specify if building for 32 bit or 64 bit. Arguments: "32" ord "64"'
    Write-Output '-clean -- specify this to clean the build folder and completely regenerate the build files'
    Write-Output '-generator -- specify the generator to use when on windows. Default ist Visual Studio 14 2015'
    Write-Output '-linux -- specify if building for linux'
}
else
{

if ((Get-ChildItem | Where-Object {$_.Name -eq "CmakeLists.txt"} | Measure-Object | % {$_.Count}) -ge 1)
{

switch ($arch) {
    "32" { 
        build32
        break
    }
    "64" {
        build64
        break
    }
    Default {
        build32
        break
    }
}
}
}