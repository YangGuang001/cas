package org.apereo.cas.config;

import org.apereo.cas.audit.AuditTrailExecutionPlanConfigurer;
import org.apereo.cas.audit.CouchDbAuditTrailManager;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.couchdb.audit.AuditActionContextCouchDbRepository;
import org.apereo.cas.couchdb.core.CouchDbConnectorFactory;

import lombok.extern.slf4j.Slf4j;
import org.apereo.inspektr.audit.AuditTrailManager;
import org.ektorp.impl.ObjectMapperFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * This is {@link CasSupportCouchDbAuditConfiguration}.
 *
 * @author Timur Duehr
 * @since 6.0.0
 */
@Configuration("casSupportCouchDbAuditConfiguration")
@EnableConfigurationProperties(CasConfigurationProperties.class)
@Slf4j
public class CasSupportCouchDbAuditConfiguration {

    @Autowired
    private CasConfigurationProperties casProperties;

    @Autowired
    @Qualifier("defaultObjectMapperFactory")
    private ObjectMapperFactory defaultObjectMapperFactory;

    @ConditionalOnMissingBean(name = "auditCouchDbFactory")
    @Bean
    @RefreshScope
    public CouchDbConnectorFactory auditCouchDbFactory() {
        return new CouchDbConnectorFactory(casProperties.getAudit().getCouchDb(), defaultObjectMapperFactory);
    }

    @ConditionalOnMissingBean(name = "auditActionContextCouchDbRepository")
    @Bean
    @RefreshScope
    public AuditActionContextCouchDbRepository auditActionContextCouchDbRepository(
        @Qualifier("auditCouchDbFactory") final CouchDbConnectorFactory auditCouchDbFactory) {
        return new AuditActionContextCouchDbRepository(auditCouchDbFactory.getCouchDbConnector(), casProperties.getAudit().getCouchDb().isCreateIfNotExists());
    }

    @ConditionalOnMissingBean(name = "couchDbAuditTrailManager")
    @Bean
    @RefreshScope
    public AuditTrailManager couchDbAuditTrailManager(@Qualifier("auditActionContextCouchDbRepository") final AuditActionContextCouchDbRepository repository) {
        repository.initStandardDesignDocument();
        return new CouchDbAuditTrailManager(repository, casProperties.getAudit().getCouchDb().isAsynchronous());
    }

    @ConditionalOnMissingBean(name = "couchDbAuditTrailExecutionPlanConfigurer")
    @Bean
    @RefreshScope
    public AuditTrailExecutionPlanConfigurer couchDbAuditTrailExecutionPlanConfigurer(
        @Qualifier("couchDbAuditTrailManager") final AuditTrailManager auditTrailManager) {
        return plan -> plan.registerAuditTrailManager(auditTrailManager);
    }
}
