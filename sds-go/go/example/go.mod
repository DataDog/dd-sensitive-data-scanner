module example-sds-go

go 1.19


require (
    github.com/DataDog/dd-sensitive-data-scanner/sds-go/go v0.0.0-20240403140050-042de62f5a24
)

replace (
    github.com/DataDog/dd-sensitive-data-scanner/sds-go/go => ../
)

