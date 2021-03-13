package main

import "testing"

func TestImageSpec(t *testing.T) {
	spec := &imageSpec{}
	if err := spec.fromString("public.ecr.aws/amazonlinux/amazonlinux:latest"); err != nil {
		t.Fatal(err)
	}
	if spec.Domain != "public.ecr.aws" || spec.Name != "amazonlinux/amazonlinux" || spec.Tag != "latest" {
		t.Fatalf("unexpected parsing result: %#v", spec)
	}
}
