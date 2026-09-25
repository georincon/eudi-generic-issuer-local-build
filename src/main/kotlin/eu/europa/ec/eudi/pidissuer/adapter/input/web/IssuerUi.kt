/*
 * Copyright (c) 2023-2026 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.europa.ec.eudi.pidissuer.adapter.input.web

import arrow.core.raise.effect
import arrow.core.raise.fold
import com.eygraber.uri.Uri
import eu.europa.ec.eudi.pidissuer.adapter.out.attestation.academic.AcademicCredentialScope
import eu.europa.ec.eudi.pidissuer.adapter.out.attestation.academic.GetAcademicDataFromDatabase
import eu.europa.ec.eudi.pidissuer.appendPath
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.input.CreateCredentialsOffer
import eu.europa.ec.eudi.pidissuer.port.out.qr.Dimensions
import eu.europa.ec.eudi.pidissuer.port.out.qr.Format
import eu.europa.ec.eudi.pidissuer.port.out.qr.GenerateQqCode
import eu.europa.ec.eudi.pidissuer.port.out.qr.Pixels
import kotlinx.coroutines.reactor.awaitSingle
import kotlinx.coroutines.reactor.awaitSingleOrNull
import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.web.reactive.function.server.*
import org.springframework.web.server.WebSession
import kotlin.io.encoding.Base64

class IssuerUi(
    private val metadata: CredentialIssuerMetaData,
    private val createCredentialsOffer: CreateCredentialsOffer,
    private val generateQrCode: GenerateQqCode,
    private val getAcademicDataFromDatabase: GetAcademicDataFromDatabase,
) {
    val router: RouterFunction<ServerResponse> =
        coRouter {
            // Redirect / to 'generate credentials offer' form
            (GET("") or GET("/")) {
                log.info("Redirecting to {}", GENERATE_CREDENTIALS_OFFER)
                ServerResponse
                    .status(HttpStatus.SEE_OTHER)
                    .renderAndAwait("redirect:$GENERATE_CREDENTIALS_OFFER")
            }

            // Display student login form
            GET(
                LOGIN,
                contentType(MediaType.ALL) and accept(MediaType.TEXT_HTML),
                ::handleDisplayLogin,
            )

            // Validate student credentials against datos_estudiantes
            POST(
                LOGIN,
                contentType(MediaType.APPLICATION_FORM_URLENCODED) and accept(MediaType.TEXT_HTML),
                ::handleLogin,
            )

            // End the student session
            (GET(LOGOUT) or POST(LOGOUT)) { handleLogout(it) }

            // Display 'generate credentials offer' form (Step 1: enter document number)
            GET(
                GENERATE_CREDENTIALS_OFFER,
                contentType(MediaType.ALL) and accept(MediaType.TEXT_HTML),
                ::handleDisplayDocumentForm,
            )

            // Step 2: Look up student by document number, show credential type selection
            POST(
                GENERATE_CREDENTIALS_OFFER,
                contentType(MediaType.APPLICATION_FORM_URLENCODED) and accept(MediaType.TEXT_HTML),
                ::handleLookupStudent,
            )

            // Step 3: Select credential type and show programs
            POST(
                SELECT_CREDENTIAL_TYPE,
                contentType(MediaType.APPLICATION_FORM_URLENCODED) and accept(MediaType.TEXT_HTML),
                ::handleSelectCredentialType,
            )

            // Step 3b: Go back from program selection to credential type selection
            GET(
                SELECT_CREDENTIAL_TYPE_BACK,
                contentType(MediaType.ALL) and accept(MediaType.TEXT_HTML),
                ::handleSelectCredentialTypeBack,
            )

            // Step 4: Save selection and generate credential offer
            POST(
                SELECT_PROGRAM,
                contentType(MediaType.APPLICATION_FORM_URLENCODED) and accept(MediaType.TEXT_HTML),
                ::handleSelectProgram,
            )
        }

    private suspend fun handleDisplayLogin(request: ServerRequest): ServerResponse {
        log.info("Displaying student login form")
        val session = request.session().awaitSingle()
        if (session.attributes[SESSION_STUDENT_USERNAME] != null) {
            return ServerResponse
                .status(HttpStatus.SEE_OTHER)
                .renderAndAwait("redirect:$GENERATE_CREDENTIALS_OFFER")
        }
        return ServerResponse
            .ok()
            .contentType(MediaType.TEXT_HTML)
            .renderAndAwait("login", emptyMap<String, Any>())
    }

    private suspend fun handleLogin(request: ServerRequest): ServerResponse {
        val formData = request.awaitFormData()
        val usuario = formData["usuario"]?.firstOrNull()?.trim().orEmpty()
        val clave = formData["clave"]?.firstOrNull().orEmpty()
        log.info("Login attempt for username: {}", usuario)

        if (usuario.isBlank() || clave.isBlank()) {
            return ServerResponse
                .badRequest()
                .contentType(MediaType.TEXT_HTML)
                .renderAndAwait(
                    "login",
                    mapOf("error" to "Debe ingresar usuario y contraseña", "usuario" to usuario),
                )
        }

        val student = getAcademicDataFromDatabase.authenticateStudent(usuario, clave)
        if (student == null) {
            log.warn("Failed login attempt for username: {}", usuario)
            return ServerResponse
                .status(HttpStatus.UNAUTHORIZED)
                .contentType(MediaType.TEXT_HTML)
                .renderAndAwait(
                    "login",
                    mapOf("error" to "Usuario o contraseña incorrectos", "usuario" to usuario),
                )
        }

        val session = request.session().awaitSingle()
        session.attributes[SESSION_STUDENT_USERNAME] = student.usuarioAutenticacion
        session.attributes[SESSION_STUDENT_FULLNAME] = "${student.nombres} ${student.apellidos}"
        log.info("Student {} logged in successfully", student.usuarioAutenticacion)

        return ServerResponse
            .status(HttpStatus.SEE_OTHER)
            .renderAndAwait("redirect:$GENERATE_CREDENTIALS_OFFER")
    }

    private suspend fun handleLogout(request: ServerRequest): ServerResponse {
        val session = request.session().awaitSingle()
        log.info("Logging out student: {}", session.attributes[SESSION_STUDENT_USERNAME])
        session.invalidate().awaitSingleOrNull()
        return ServerResponse
            .status(HttpStatus.SEE_OTHER)
            .renderAndAwait("redirect:$LOGIN")
    }

    private suspend fun ServerRequest.requireStudentSession(): WebSession? {
        val session = session().awaitSingle()
        return if (session.attributes[SESSION_STUDENT_USERNAME] != null) session else null
    }

    private suspend fun handleDisplayDocumentForm(request: ServerRequest): ServerResponse {
        val session = request.requireStudentSession()
            ?: return ServerResponse.status(HttpStatus.SEE_OTHER).renderAndAwait("redirect:$LOGIN")

        log.info("Displaying document number lookup form")
        val usefulLinks = createUsefulLinks(metadata.id, metadata.authorizationServers[0])
        return ServerResponse
            .ok()
            .contentType(MediaType.TEXT_HTML)
            .renderAndAwait(
                "generate-credentials-offer-form",
                mapOf(
                    "credentialsOfferUri" to createCredentialsOffer.defaultCredentialOfferUri.toString(),
                    "openid4VciVersion" to OpenId4VciSpec.VERSION,
                    "usefulLinks" to usefulLinks,
                    "studentFullName" to session.attributes[SESSION_STUDENT_FULLNAME],
                ),
            )
    }

    private suspend fun handleLookupStudent(request: ServerRequest): ServerResponse {
        request.requireStudentSession()
            ?: return ServerResponse.status(HttpStatus.SEE_OTHER).renderAndAwait("redirect:$LOGIN")

        log.info("Looking up student by document number")
        val formData = request.awaitFormData()
        val documentoIdentidad = formData["documentoIdentidad"]?.firstOrNull()?.trim().orEmpty()
        val credentialsOfferUri = formData["credentialsOfferUri"]?.firstOrNull { it.isNotBlank() }

        if (documentoIdentidad.isBlank()) {
            return ServerResponse
                .badRequest()
                .contentType(MediaType.TEXT_HTML)
                .renderAndAwait(
                    "generate-credentials-offer-form",
                    mapOf(
                        "error" to "Debe ingresar un número de documento válido",
                        "credentialsOfferUri" to (credentialsOfferUri ?: createCredentialsOffer.defaultCredentialOfferUri.toString()),
                        "openid4VciVersion" to OpenId4VciSpec.VERSION,
                    ),
                )
        }

        val student = getAcademicDataFromDatabase.findStudentByDocumentNumber(documentoIdentidad)
        if (student == null) {
            return ServerResponse
                .ok()
                .contentType(MediaType.TEXT_HTML)
                .renderAndAwait(
                    "generate-credentials-offer-form",
                    mapOf(
                        "error" to "No se encontró estudiante con documento: $documentoIdentidad",
                        "credentialsOfferUri" to (credentialsOfferUri ?: createCredentialsOffer.defaultCredentialOfferUri.toString()),
                        "openid4VciVersion" to OpenId4VciSpec.VERSION,
                    ),
                )
        }

        val usefulLinks = createUsefulLinks(metadata.id, metadata.authorizationServers[0])
        return ServerResponse
            .ok()
            .contentType(MediaType.TEXT_HTML)
            .renderAndAwait(
                "select-credential-type",
                mapOf(
                    "student" to student,
                    "credentialsOfferUri" to (credentialsOfferUri ?: createCredentialsOffer.defaultCredentialOfferUri.toString()),
                    "openid4VciVersion" to OpenId4VciSpec.VERSION,
                    "usefulLinks" to usefulLinks,
                ),
            )
    }

    private suspend fun handleSelectCredentialType(request: ServerRequest): ServerResponse {
        request.requireStudentSession()
            ?: return ServerResponse.status(HttpStatus.SEE_OTHER).renderAndAwait("redirect:$LOGIN")

        log.info("Selecting credential type and loading programs")
        val formData = request.awaitFormData()
        val usuarioAutenticacion = formData["usuarioAutenticacion"]?.firstOrNull().orEmpty()
        val numeroIdentificacion = formData["numeroIdentificacion"]?.firstOrNull().orEmpty()
        val credentialType = formData["credentialType"]?.firstOrNull().orEmpty()
        val credentialsOfferUri = formData["credentialsOfferUri"]?.firstOrNull()

        val student = getAcademicDataFromDatabase.findStudentByDocumentNumber(numeroIdentificacion)
        if (student == null) {
            return ServerResponse
                .ok()
                .contentType(MediaType.TEXT_HTML)
                .renderAndAwait(
                    "generate-credentials-offer-form",
                    mapOf(
                        "error" to "No se encontró estudiante con documento: $numeroIdentificacion",
                        "credentialsOfferUri" to (credentialsOfferUri ?: createCredentialsOffer.defaultCredentialOfferUri.toString()),
                        "openid4VciVersion" to OpenId4VciSpec.VERSION,
                    ),
                )
        }

        val programs = getAcademicDataFromDatabase.findStudentPrograms(student.usuarioAutenticacion)
        if (programs.isEmpty()) {
            return ServerResponse
                .ok()
                .contentType(MediaType.TEXT_HTML)
                .renderAndAwait(
                    "generate-credentials-offer-form",
                    mapOf(
                        "error" to "No se encontraron registros académicos para el estudiante",
                        "credentialsOfferUri" to (credentialsOfferUri ?: createCredentialsOffer.defaultCredentialOfferUri.toString()),
                        "openid4VciVersion" to OpenId4VciSpec.VERSION,
                    ),
                )
        }

        val usefulLinks = createUsefulLinks(metadata.id, metadata.authorizationServers[0])
        return ServerResponse
            .ok()
            .contentType(MediaType.TEXT_HTML)
            .renderAndAwait(
                "select-academic-program",
                mapOf(
                    "student" to student,
                    "programs" to programs,
                    "credentialType" to credentialType,
                    "credentialsOfferUri" to (credentialsOfferUri ?: createCredentialsOffer.defaultCredentialOfferUri.toString()),
                    "openid4VciVersion" to OpenId4VciSpec.VERSION,
                    "usefulLinks" to usefulLinks,
                ),
            )
    }

    private suspend fun handleSelectCredentialTypeBack(request: ServerRequest): ServerResponse {
        request.requireStudentSession()
            ?: return ServerResponse.status(HttpStatus.SEE_OTHER).renderAndAwait("redirect:$LOGIN")

        log.info("Going back to credential type selection")
        val usuarioAutenticacion = request.queryParam("usuarioAutenticacion").orElse("").orEmpty()
        val numeroIdentificacion = request.queryParam("numeroIdentificacion").orElse("").orEmpty()
        val tipoDocumento = request.queryParam("tipoDocumento").orElse("").orEmpty()
        val credentialsOfferUri = request.queryParam("credentialsOfferUri").orElse("")

        val student = getAcademicDataFromDatabase.findStudentByDocumentNumber(numeroIdentificacion)
        if (student == null) {
            return ServerResponse
                .status(HttpStatus.SEE_OTHER)
                .renderAndAwait("redirect:$GENERATE_CREDENTIALS_OFFER")
        }

        val usefulLinks = createUsefulLinks(metadata.id, metadata.authorizationServers[0])
        return ServerResponse
            .ok()
            .contentType(MediaType.TEXT_HTML)
            .renderAndAwait(
                "select-credential-type",
                mapOf(
                    "student" to student,
                    "credentialsOfferUri" to (credentialsOfferUri.ifBlank { createCredentialsOffer.defaultCredentialOfferUri.toString() }),
                    "openid4VciVersion" to OpenId4VciSpec.VERSION,
                    "usefulLinks" to usefulLinks,
                ),
            )
    }

    private suspend fun handleSelectProgram(request: ServerRequest): ServerResponse {
        request.requireStudentSession()
            ?: return ServerResponse.status(HttpStatus.SEE_OTHER).renderAndAwait("redirect:$LOGIN")

        log.debug("Saving selection and generating credential offer")
        val formData = request.awaitFormData()
        val usuarioAutenticacion = formData["usuarioAutenticacion"]?.firstOrNull().orEmpty()
        val numeroIdentificacion = formData["numeroIdentificacion"]?.firstOrNull().orEmpty()
        val programmaId = formData["programaId"]?.firstOrNull()?.toLongOrNull() ?: 0L
        val historialId = formData["historialId"]?.firstOrNull()?.toLongOrNull() ?: 0L
        val credentialsOfferUri = formData["credentialsOfferUri"]?.firstOrNull()

        getAcademicDataFromDatabase.saveSelection(
            usuarioAutenticacion,
            numeroIdentificacion,
            programmaId,
            historialId,
        )

        return effect<CreateCredentialsOffer.Error, Uri> {
            val credentialIds = setOf(CredentialConfigurationId(AcademicCredentialScope.value))
            val createCredentialOfferRequest = CreateCredentialsOffer.Request(credentialIds, credentialsOfferUri)
            createCredentialsOffer(createCredentialOfferRequest)
        }.fold(
            transform = { credentialsOfferUri ->
                context(generateQrCode) { credentialsOfferUri.credentialOfferSuccessResponse() }
            },
            recover = { error ->
                log.warn("Unable to generate Credentials Offer. Error: {}", error)
                error.credentialOfferErrorResponse()
            },
        )
    }

    private fun createUsefulLinks(
        credentialIssuer: CredentialIssuerId,
        authorizationServer: HttpsUrl,
    ): Map<String, String> {
        fun HttpsUrl.wellKnown(path: String): HttpsUrl =
            HttpsUrl.unsafe(
                value
                    .buildUpon()
                    .path(null)
                    .appendPath(".well-known")
                    .appendPath(path)
                    .apply {
                        value.pathSegments
                            .filterNot { it.isBlank() }
                            .forEach { appendPath(it) }
                    }.build()
                    .toString(),
            )

        val credentialIssuerMetadata = credentialIssuer.wellKnown("openid-credential-issuer")
        val protectedResourceMetadata = credentialIssuer.wellKnown("oauth-protected-resource")
        val authorizationServerMetadata = authorizationServer.wellKnown("oauth-authorization-server")
        val sdJwtVcIssuerMetadata = credentialIssuer.wellKnown("jwt-vc-issuer")

        return mapOf(
            "credential_issuer_metadata" to credentialIssuerMetadata.externalForm,
            "protected_resource_metadata" to protectedResourceMetadata.externalForm,
            "authorization_server_metadata" to authorizationServerMetadata.externalForm,
            "sdjwt_vc_issuer_metadata" to sdJwtVcIssuerMetadata.externalForm,
        )
    }

    companion object {
        const val LOGIN: String = "/issuer/login"
        const val LOGOUT: String = "/issuer/logout"
        const val GENERATE_CREDENTIALS_OFFER: String = "/issuer/credentialsOffer/generate"
        const val SELECT_CREDENTIAL_TYPE: String = "/issuer/credentialsOffer/selectCredentialType"
        const val SELECT_CREDENTIAL_TYPE_BACK: String = "/issuer/credentialsOffer/selectCredentialTypeBack"
        const val SELECT_PROGRAM: String = "/issuer/credentialsOffer/selectProgram"
        private const val SESSION_STUDENT_USERNAME: String = "studentUsername"
        private const val SESSION_STUDENT_FULLNAME: String = "studentFullName"
        private val log = LoggerFactory.getLogger(IssuerUi::class.java)
    }
}

context(generateQrCode: GenerateQqCode)
private suspend fun Uri.credentialOfferSuccessResponse(): ServerResponse {
    val uri = this@credentialOfferSuccessResponse
    val qrCode = generateQrCode(uri, Format.PNG, Dimensions(Pixels(300u), Pixels(300u)))
    return ServerResponse
        .ok()
        .contentType(MediaType.TEXT_HTML)
        .renderAndAwait(
            "display-credentials-offer",
            mapOf(
                "uri" to uri.toString(),
                "qrCode" to Base64.encode(qrCode),
                "qrCodeMediaType" to "image/png",
            ),
        )
}

private suspend fun CreateCredentialsOffer.Error.credentialOfferErrorResponse(): ServerResponse =
    ServerResponse
        .badRequest()
        .contentType(MediaType.TEXT_HTML)
        .renderAndAwait(
            "generate-credentials-offer-error",
            mapOf(
                "error" to this::class.java.canonicalName,
                "openid4VciVersion" to OpenId4VciSpec.VERSION,
            ),
        )
