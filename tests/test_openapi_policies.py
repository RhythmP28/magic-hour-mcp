import unittest
from types import SimpleNamespace
from unittest.mock import patch

from mcp_magichour import openapi_policies
from mcp_magichour.openapi_policies import (
    LOGGING_GUIDANCE,
    READ_ONLY_LOGGING_GUIDANCE,
    apply_magic_hour_policies,
    customize_openapi_component,
    is_read_operation,
    logging_guidance,
    normalize_mcp_tool_name,
    tool_annotations,
)

READ_ONLY_PATHS = (
    "/v1/account",
    "/v1/face-detection/{id}",
    "/v1/video-projects/{id}",
    "/v1/image-projects/{id}",
    "/v1/audio-projects/{id}",
)


class OpenApiPolicyTests(unittest.TestCase):
    def test_generation_post_gets_polling_guidance(self):
        spec = {
            "paths": {
                "/v1/ai-image-generator": {
                    "post": {
                        "tags": ["Image Projects"],
                        "operationId": "aiImageGenerator.createImage",
                        "description": "Create an image.",
                    }
                }
            }
        }

        patched = apply_magic_hour_policies(spec)
        operation_id = patched["paths"]["/v1/ai-image-generator"]["post"]["operationId"]
        description = patched["paths"]["/v1/ai-image-generator"]["post"]["description"]

        self.assertEqual(operation_id, "ai_image_generator_create_image")
        self.assertIn("MCP guidance", description)
        self.assertIn("wait_for_image_project", description)
        self.assertIn("complete", description)

    def test_file_path_inputs_get_upload_guidance(self):
        spec = {
            "paths": {
                "/v1/image-to-video": {
                    "post": {
                        "tags": ["Video Projects"],
                        "description": "Animate an image.",
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "properties": {
                                            "image_file_path": {"type": "string"}
                                        }
                                    }
                                }
                            }
                        },
                    }
                }
            }
        }

        patched = apply_magic_hour_policies(spec)
        description = patched["paths"]["/v1/image-to-video"]["post"]["description"]

        self.assertIn("upload-URL endpoint", description)
        self.assertIn("file_path", description)
        self.assertIn("Direct public media URLs may work", description)
        self.assertIn("hotlinked URLs can fail", description)

    def test_custom_component_adds_group_tags(self):
        class Route:
            method = "POST"
            path = "/v1/text-to-video"
            tags = ["Video Projects"]

        class Component:
            tags = set()

        component = Component()
        customize_openapi_component(Route(), component)

        self.assertIn("magic-hour", component.tags)
        self.assertIn("write-operation", component.tags)
        self.assertIn("generation", component.tags)

    def test_unknown_project_post_gets_group_policy_without_endpoint_specific_config(
        self,
    ):
        spec = {
            "paths": {
                "/v1/new-video-tool": {
                    "post": {
                        "tags": ["Video Projects"],
                        "operationId": "newVideoTool.createVideo",
                        "description": "Create a new kind of video.",
                    }
                }
            }
        }

        patched = apply_magic_hour_policies(spec)
        description = patched["paths"]["/v1/new-video-tool"]["post"]["description"]

        self.assertIn("wait_for_video_project", description)
        self.assertIn("GET /v1/video-projects/{id}", description)

    def test_tool_names_are_snake_case_and_replace_generic_actions(self):
        self.assertEqual(
            normalize_mcp_tool_name("faceDetection.getDetails"),
            "face_detection_retrieve_details",
        )
        self.assertEqual(
            normalize_mcp_tool_name("videoAssets.generatePresignedUrl"),
            "video_assets_generate_presigned_url",
        )

    def test_tool_names_must_have_at_least_four_characters(self):
        with self.assertRaisesRegex(ValueError, "at least 4 characters"):
            normalize_mcp_tool_name("id")

    def test_unreviewed_operation_fails_closed(self):
        for method, path, tags in (
            ("POST", "/v1/publish", []),
            ("POST", "/v1/publish", ["Video Projects"]),
            ("GET", "/v1/account/usage", ["Account"]),
            ("PATCH", "/v1/video-projects/{id}", ["Video Projects"]),
        ):
            with self.assertRaisesRegex(ValueError, "Review MCP side effects"):
                customize_openapi_component(
                    SimpleNamespace(method=method, path=path, tags=tags),
                    SimpleNamespace(tags=set()),
                )

    def test_tool_annotations_distinguish_reads_writes_and_deletes(self):
        expected = {
            "read": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False},
            "write": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False},
            "delete": {"readOnlyHint": False, "destructiveHint": True, "openWorldHint": False},
        }
        actual = {
            "read": tool_annotations(read_only=True),
            "write": tool_annotations(read_only=False),
            "delete": tool_annotations(read_only=False, destructive=True),
        }
        for kind, annotations in actual.items():
            self.assertEqual(annotations.model_dump(by_alias=True, exclude_none=True), expected[kind], kind)
        with self.assertRaisesRegex(ValueError, "read-only tool cannot also be destructive"):
            tool_annotations(read_only=True, destructive=True)

    def test_diagnostic_logging_flag_restores_all_write_hints(self):
        self.assertFalse(openapi_policies.DIAGNOSTIC_LOGGING_COUNTS_AS_WRITE)
        self.assertTrue(tool_annotations(read_only=True).readOnlyHint)
        self.assertEqual(logging_guidance(read_only=True), READ_ONLY_LOGGING_GUIDANCE)
        self.assertEqual(logging_guidance(read_only=False), LOGGING_GUIDANCE)

        with patch.object(openapi_policies, "DIAGNOSTIC_LOGGING_COUNTS_AS_WRITE", True):
            self.assertFalse(tool_annotations(read_only=True).readOnlyHint)
            self.assertFalse(tool_annotations(read_only=False).readOnlyHint)
            self.assertTrue(tool_annotations(read_only=False, destructive=True).destructiveHint)
            self.assertEqual(logging_guidance(read_only=True), LOGGING_GUIDANCE)
            self.assertEqual(logging_guidance(read_only=False), LOGGING_GUIDANCE)

            component = SimpleNamespace(tags=set())
            customize_openapi_component(
                SimpleNamespace(method="GET", path="/v1/account", tags=["Account"]), component
            )
            self.assertFalse(component.annotations.readOnlyHint)

    def test_reviewed_reads_are_derived_from_method_and_path(self):
        for path in READ_ONLY_PATHS:
            with self.subTest(path=path):
                self.assertTrue(is_read_operation("GET", path))
                self.assertFalse(is_read_operation("DELETE", path))
                self.assertFalse(is_read_operation("POST", path))
                component = SimpleNamespace(tags=set())
                customize_openapi_component(
                    SimpleNamespace(method="GET", path=path, tags=[]), component
                )
                self.assertEqual(
                    component.annotations.model_dump(by_alias=True, exclude_none=True),
                    {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False},
                )
                self.assertIn("magic-hour", component.tags)
                self.assertNotIn("write-operation", component.tags)
        self.assertFalse(is_read_operation("GET", "/v1/files/upload-urls"))
        self.assertFalse(is_read_operation("GET", "/v1/ai-image-generator"))

    def test_writes_and_deletes_are_never_read_only(self):
        cases = (
            ("POST", "/v1/files/upload-urls", ["Files"], False),
            ("POST", "/v1/face-detection", ["Files"], False),
            ("POST", "/v1/ai-image-generator", ["Image Projects"], False),
            ("POST", "/v1/video-to-video", ["Video Projects"], False),
            ("DELETE", "/v1/video-projects/{id}", ["Video Projects"], True),
            ("DELETE", "/v1/image-projects/{id}", ["Image Projects"], True),
            ("DELETE", "/v1/audio-projects/{id}", ["Audio Projects"], True),
        )
        for method, path, tags, destructive in cases:
            with self.subTest(method=method, path=path):
                component = SimpleNamespace(tags=set())
                customize_openapi_component(
                    SimpleNamespace(method=method, path=path, tags=tags), component
                )
                self.assertFalse(component.annotations.readOnlyHint)
                self.assertFalse(component.annotations.openWorldHint)
                self.assertEqual(component.annotations.destructiveHint, destructive)

    def test_read_operations_get_read_only_logging_guidance(self):
        spec = {
            "paths": {
                "/v1/account": {
                    "get": {
                        "tags": ["Account"],
                        "operationId": "account.get",
                        "description": "Get the current credit balance.",
                    }
                },
                "/v1/video-projects/{id}": {
                    "get": {
                        "tags": ["Video Projects"],
                        "operationId": "videoProjects.getDetails",
                        "description": "Get a video project.",
                    },
                    "delete": {
                        "tags": ["Video Projects"],
                        "operationId": "videoProjects.delete",
                        "description": "Delete a video project.",
                    },
                },
                "/v1/ai-image-generator": {
                    "post": {
                        "tags": ["Image Projects"],
                        "operationId": "aiImageGenerator.createImage",
                        "description": "Create an image.",
                    }
                },
            }
        }

        patched = apply_magic_hour_policies(spec)["paths"]
        account = patched["/v1/account"]["get"]
        details = patched["/v1/video-projects/{id}"]["get"]
        delete = patched["/v1/video-projects/{id}"]["delete"]
        create = patched["/v1/ai-image-generator"]["post"]

        self.assertEqual(account["operationId"], "account_retrieve")
        for read in (account, details):
            self.assertIn(READ_ONLY_LOGGING_GUIDANCE, read["description"])
            self.assertNotIn(LOGGING_GUIDANCE, read["description"])
        self.assertIn("credit balance and subscription tier", account["description"])
        self.assertIn("It does not change the account.", account["description"])
        for write in (delete, create):
            self.assertIn(LOGGING_GUIDANCE, write["description"])
            self.assertNotIn(READ_ONLY_LOGGING_GUIDANCE, write["description"])


if __name__ == "__main__":
    unittest.main()
