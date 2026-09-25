CREATE TABLE IF NOT EXISTS academic_credential (
    id                          BIGSERIAL PRIMARY KEY,
    credential_format           VARCHAR(255)  NOT NULL,
    credential_type             VARCHAR(255)  NOT NULL,
    issued_at                   TIMESTAMP WITH TIME ZONE NOT NULL,
    expires_at                  TIMESTAMP WITH TIME ZONE NOT NULL,
    notification_id             VARCHAR(255),
    status_list_uri             VARCHAR(2048),
    status_list_index           BIGINT,
    client_status_list_uri      VARCHAR(2048) NOT NULL,
    client_status_list_index    BIGINT        NOT NULL,
    key_storage_status_list_uri   VARCHAR(2048),
    key_storage_status_list_index BIGINT,
    credential_identifier       UUID          NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_academic_credential_notification_id ON academic_credential (notification_id);
CREATE INDEX IF NOT EXISTS idx_academic_credential_expires_at ON academic_credential (expires_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_academic_credential_uuid ON academic_credential (credential_identifier);