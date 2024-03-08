module example-sds-go

go 1.19


require (
    github.com/DataDog/datadog-agent/pkg/sds v0.0.0
)

replace (
    github.com/DataDog/datadog-agent/pkg/sds => ../
)

